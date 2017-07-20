'''
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
from collections import namedtuple
from copy import deepcopy

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.parsers import get_parser


# Set the below to True when we want to support matching on multiple schemas
# and then log_patterns will be used as a fall back for key/value matching
SUPPORT_MULTIPLE_SCHEMA_MATCHING = False


class InvalidSchemaError(Exception):
    """Raise this exception if a declared schema field type does not match
    the data passed."""
    pass


class StreamClassifier(object):
    """Classify, map source, and parse a raw record into its declared type."""

    def __init__(self, config):
        self._config = config
        self._entity_log_sources = []

    @staticmethod
    def extract_service_and_entity(raw_record):
        """Map a record to its originating AWS service and entity.

        Each raw record contains a set of keys to represent its source.
        A Kinesis record will contain a `kinesis` key while a
        S3 record contains `s3`.

        Sets:
            payload.service: The AWS service which sent the record
            payload.entity: The specific instance of a service which sent the record

        Args:
            payload: A StreamPayload object

        Returns:
            [boolean] True if the service and entity for this payload were mapped properly
        """
        # Sns is capitalized below because this is how AWS stores it within the Record
        # Other services, like s3, are not stored like this. Do not alter it!
        entity_mapper = {
            'kinesis': lambda r: r['eventSourceARN'].split('/')[1],
            's3': lambda r: r['s3']['bucket']['name'],
            'Sns': lambda r: r['EventSubscriptionArn'].split(':')[5]
        }

        service, entity = '', ''
        # check raw record for either kinesis, s3, or sns keys
        for key, map_function in entity_mapper.iteritems():
            if key in raw_record:
                service = key.lower()
                # map the entity name from a record
                entity = map_function(raw_record)
                break

        return service, entity

    def load_sources(self, payload):
        """Load the sources for this payload.

        Args:
            payload: A StreamPayload object

        Returns:
            [boolean] True if the entity's log sources loaded properly
        """
        # Clear the list from any previous runs
        del self._entity_log_sources[:]

        # get all logs for the configured service/entity (s3, kinesis, or sns)
        service_entities = self._config['sources'].get(payload.service)
        if not service_entities:
            LOGGER.error('Service not declared in sources configuration: %s',
                         payload.service)
            return False

        config_entity = service_entities.get(payload.entity)
        if not config_entity:
            LOGGER.error('Entity [%s] not declared in sources configuration for service: %s',
                         payload.entity,
                         payload.service)
            return False

        self._entity_log_sources = config_entity['logs']

        return bool(self._entity_log_sources)

    def _get_log_info_for_source(self):
        """Return a mapping of all log sources to a given entity with attributes.

        Args:
            payload: A StreamAlert payload object to be mapped

        Returns:
            (dict) log sources and their attributes for the entity:
            {
                'log_source_1': {
                    'parser': 'json',
                    'keys': [ 'key1', 'key2', ..., 'keyn']
                },
                'log_source_n': {
                    'parser': 'csv',
                    'keys': ['field1', 'field2', ..., 'fieldn'],
                    'log_patterns': ['*pattern1*']
                }
            }
        """
        # Make a copy of the log entries to be modified
        config_logs = deepcopy(self._config['logs'])

        for log_source in config_logs.keys():
            category = log_source.split(':')[0]
            # Remove this log type if it's not one of the sources for this entity
            if not category in self._entity_log_sources:
                del config_logs[log_source]

        return config_logs

    def classify_record(self, payload, data):
        """Classify and type raw record passed into StreamAlert.

        Before we apply our rules to a record passed to the lambda function,
        we need to validate a record.  Validation requires verifying its source,
        checking that we have declared it in our configuration, and indeitifying
        the record's data source and parsing its data type.

        Args:
            payload: A StreamAlert payload object
            data: Pre parsed data string from a raw_event to be parsed
        """
        parse_result = self._parse(payload, data)
        if all([parse_result,
                payload.service,
                payload.entity,
                payload.type,
                payload.log_source,
                payload.records]):
            payload.valid = True

        LOGGER.debug('payload: %s', payload)

    def _check_valid_parse(self, valid_parses):
        """Check to see if there are multiple schemas that have validly parsed this
        log. If so, fall back on using log_patterns to look for the proper log. If no
        log_patterns exist, or they do not resolve the problem, fall back on using the
        first matched schema.

        Args:
            [valid_parses] A list of tuples containing the info for schemas that have
                validly parsed this record. Each tuple is: (log_name, parser, parsed_data)

        Returns:
            [tuple] The proper tuple to use for parsing from the list of tuples
        """
        # If there is only one parse or we do not have support for multiple schemas
        # enabled, then just return the first parse that was valid
        if len(valid_parses) == 1 or not SUPPORT_MULTIPLE_SCHEMA_MATCHING:
            return valid_parses[0]

        matched_parses = []
        for i, valid_parse in enumerate(valid_parses):
            log_patterns = valid_parse.parser.options.get('log_patterns', {})
            if (all(valid_parse.parser.matched_log_pattern(data, log_patterns)
                    for data in valid_parse.parsed_data)):
                matched_parses.append(valid_parses[i])
            else:
                LOGGER.debug('log pattern matching failed for schema: %s', valid_parse.root_schema)

        if matched_parses:
            if len(matched_parses) > 1:
                LOGGER.error('log patterns matched for multiple schemas: %s',
                             ', '.join(parse.log_name for parse in matched_parses))
                LOGGER.error('proceeding with schema for: %s', matched_parses[0].log_name)

            return matched_parses[0]

        LOGGER.error('log classification matched for multiple schemas: %s',
                     ', '.join(parse.log_name for parse in valid_parses))
        LOGGER.error('proceeding with schema for: %s', valid_parses[0].log_name)

        return valid_parses[0]

    def _process_log_schemas(self, payload, data):
        """Get any log schemas that matched this log format

        Args:
            payload: A StreamAlert payload object
            data: Pre parsed data string from a raw_event to be parsed

        Returns:
            [list] A list containing any schemas that matched this log format
                Each list entry contains the namedtuple of 'ClassifiedLog' with
                values of log_name, root_schema, parser, and parsed_data
        """
        classified_log = namedtuple('ClassifiedLog', 'log_name, root_schema, parser, parsed_data')
        valid_parses = []

        # Loop over all logs declared in logs.json
        for log_name, attributes in self._get_log_info_for_source().iteritems():
            # Get the parser type to use for this log
            parser_name = payload.type or attributes['parser']

            schema = attributes['schema']
            options = attributes.get('configuration', {})

            # Setup the parser class
            parser_class = get_parser(parser_name)
            parser = parser_class(options)

            # Get a list of parsed records
            parsed_data = parser.parse(schema, data)

            LOGGER.debug('Schema: %s', schema)
            if not parsed_data:
                continue

            if SUPPORT_MULTIPLE_SCHEMA_MATCHING:
                valid_parses.append(classified_log(log_name, schema, parser, parsed_data))
                continue

            log_patterns = parser.options.get('log_patterns')
            if all(parser.matched_log_pattern(rec, log_patterns) for rec in parsed_data):
                return [classified_log(log_name, schema, parser, parsed_data)]

        return valid_parses

    def _parse(self, payload, data):
        """Parse a record into a declared type.

        Args:
            payload: A StreamAlert payload object
            data: Pre parsed data string from a raw_event to be parsed

        Sets:
            payload.log_source: The detected log name from the data_sources config.
            payload.type: The record's type.
            payload.records: The parsed record.

        Returns:
            A boolean representing the success of the parse.
        """
        valid_parses = self._process_log_schemas(payload, data)

        if not valid_parses:
            return False

        valid_parse = self._check_valid_parse(valid_parses)

        LOGGER.debug('Log name: %s', valid_parse.log_name)
        LOGGER.debug('Parsed data: %s', valid_parse.parsed_data)

        for parsed_data_value in valid_parse.parsed_data:
            # Convert data types per the schema
            # Use the root schema for the parser due to updates caused by
            # configuration settings such as envelope_keys and optional_keys
            if not self._convert_type(
                    parsed_data_value,
                    valid_parse.parser.type(),
                    valid_parse.root_schema,
                    valid_parse.parser.options):
                return False

        payload.log_source = valid_parse.log_name
        payload.type = valid_parse.parser.type()
        payload.records = valid_parse.parsed_data

        return True

    def _convert_type(self, payload, parser_type, schema, options):
        """Convert a parsed payload's values into their declared types.

        If the schema is incorrectly defined for a particular field,
        this function will return False which will make the payload
        invalid.

        Args:
            parsed_data: Parsed payload dict
            schema: data schema for a specific log source
            options: parser options dict

        Returns:
            parsed dict payload with typed values
        """
        # check for list types here
        for key, value in schema.iteritems():
            key = str(key)
            # if the schema value is declared as string
            if value == 'string':
                payload[key] = str(payload[key])

            # if the schema value is declared as integer
            elif value == 'integer':
                try:
                    payload[key] = int(payload[key])
                except ValueError:
                    LOGGER.error('Invalid schema - %s is not an int', key)
                    return False

            elif value == 'float':
                try:
                    payload[key] = float(payload[key])
                except ValueError:
                    LOGGER.error('Invalid schema - %s is not a float', key)
                    return False

            elif value == 'boolean':
                payload[key] = str(payload[key]).lower() == 'true'

            elif isinstance(value, dict):
                if not value:
                    continue # allow empty maps (dict)

                # handle nested values
                # skip the 'streamalert:envelope_keys' key that we've added during parsing
                if key == 'streamalert:envelope_keys' and isinstance(payload[key], dict):
                    continue

                if 'log_patterns' in options:
                    options['log_patterns'] = options['log_patterns'][key]

                self._convert_type(payload[key], parser_type, schema[key], options)

            elif isinstance(value, list):
                pass

            else:
                LOGGER.error('Unsupported schema type: %s', value)

        return True
