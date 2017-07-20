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


class StreamPayload(object):
    """Container class for the StreamAlert payload object.

    Attributes:
        raw_record: The record from the AWS Lambda Records dictionary.

        valid: A boolean representing if the record is deemed valid by
            parsing and classification.

        service: The aws service where the record originated from. Can be
            either S3 or kinesis.

        entity: The instance of the sending service. Can be either a
            specific kinesis stream or S3 bucket name.

        log_source: The name of the logging application which the data
            originated from.  This could be osquery, auditd, etc.

        type: The data type of the record - json, csv, syslog, etc.

        record: A list of parsed and typed record(s).

    Public Methods:
        refresh_record
    """
    def __init__(self, **kwargs):
        """
        Keyword Args:
            raw_record (dict): The record to be parsed - in AWS event format
        """
        self.raw_record = kwargs['raw_record']
        self.service = kwargs['service']
        self.entity = kwargs['entity']

        self.type = None
        self.log_source = None
        self.records = None
        self.valid = False

    def __repr__(self):
        repr_str = ('<StreamPayload valid:{} log_source:{} entity:{} '
                    'type:{} record:{}>').format(self.valid, self.log_source,
                                                 self.entity, self.type, self.records)

        return repr_str

    def refresh_record(self, new_record):
        """Replace the currently loaded record with a new one.

        Used mainly when S3 is used as a source, due to looping over files
        downloadd from S3 events verses all records being readily available
        from a Kinesis stream.

        Args:
            new_record (str): A new raw record to be parsed
        """
        self.raw_record = new_record
        self.type = None
        self.log_source = None
        self.records = None
        self.valid = False
