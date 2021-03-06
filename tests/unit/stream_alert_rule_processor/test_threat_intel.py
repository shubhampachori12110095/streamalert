"""
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
"""
# pylint: disable=protected-access,no-self-use
from botocore.exceptions import ClientError
from mock import patch
from nose.tools import (
    assert_equal,
    assert_false,
    assert_true,
    raises,
)

from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.threat_intel import StreamThreatIntel, StreamIoc
from tests.unit.stream_alert_rule_processor.test_helpers import (
    MockDynamoDBClient,
    mock_normalized_records,
)


class TestStreamIoc(object):
    """Test class for StreamIoc which store IOC info"""
    def test_instance_initialization(self):
        """StreamIoc - Test StreamIoc initialization"""
        ioc = StreamIoc()
        assert_equal(ioc.value, None)
        assert_equal(ioc.ioc_type, None)
        assert_equal(ioc.sub_type, None)
        assert_equal(ioc.associated_record, None)
        assert_false(ioc.is_ioc)

        new_ioc = StreamIoc(value='1.1.1.2', ioc_type='ip',
                            associated_record={'foo': 'bar'}, is_ioc=True)
        assert_equal(new_ioc.value, '1.1.1.2')
        assert_equal(new_ioc.ioc_type, 'ip')
        assert_equal(new_ioc.associated_record, {'foo': 'bar'})
        assert_true(new_ioc.is_ioc)

    def test_set_properties(self):
        """StreamIoc - Test setter of class properties"""
        ioc = StreamIoc(value='evil.com', ioc_type='domain',
                        associated_record={'foo': 'bar'}, is_ioc=True)
        ioc.value = 'evil.com'
        assert_equal(ioc.value, 'evil.com')
        ioc.ioc_type = 'test_ioc_type'
        assert_equal(ioc.ioc_type, 'test_ioc_type')
        ioc.associated_record = None
        assert_equal(ioc.associated_record, None)
        ioc.is_ioc = False
        assert_false(ioc.is_ioc)

class TestStreamThreatIntel(object):
    """Test class for StreamThreatIntel"""
    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.config = None
        cls.threat_intel = None

    def setup(self):
        """Setup before each method"""
        # Clear out the cached matchers and rules to avoid conflicts with production code
        self.config = load_config('tests/unit/conf')
        self.config['global']['threat_intel']['enabled'] = True
        self.threat_intel = StreamThreatIntel.load_from_config(self.config)

    def teardown(self):
        StreamThreatIntel._StreamThreatIntel__normalized_types.clear() # pylint: disable=no-member

    @patch('boto3.client')
    def test_threat_detection(self, mock_client):
        """Threat Intel - Test threat_detection method"""
        records = mock_normalized_records()
        threat_intel = StreamThreatIntel.load_from_config(self.config)
        mock_client('dynamodb').batch_get_item.return_value = MockDynamoDBClient.response()

        assert_equal(len(threat_intel.threat_detection(records)), 2)

    def test_insert_ioc_info(self):
        """Threat Intel - Insert IOC info to a record"""
        # rec has no IOC info
        rec = {
            'key1': 'foo',
            'key2': 'bar'
        }

        self.threat_intel._insert_ioc_info(rec, 'ip', '1.2.3.4')
        expected_results = {
            "ip": ['1.2.3.4']
        }
        assert_equal(rec['streamalert:ioc'], expected_results)

        # rec has IOC info and new info is duplicated
        rec_with_ioc_info = {
            'key1': 'foo',
            'key2': 'bar',
            'streamalert:ioc': {
                'ip': ['1.2.3.4']
            }
        }

        self.threat_intel._insert_ioc_info(rec_with_ioc_info, 'ip', '1.2.3.4')
        expected_results = {
            "ip": ['1.2.3.4']
        }
        assert_equal(rec_with_ioc_info['streamalert:ioc'], expected_results)

        # rec has IOC info
        rec_with_ioc_info = {
            'key1': 'foo',
            'key2': 'bar',
            'streamalert:ioc': {
                'ip': ['4.3.2.1']
            }
        }

        self.threat_intel._insert_ioc_info(rec_with_ioc_info, 'ip', '1.2.3.4')
        expected_results = {
            "ip": ['4.3.2.1', '1.2.3.4']
        }
        assert_equal(rec_with_ioc_info['streamalert:ioc'], expected_results)

    def test_extract_ioc_from_record(self):
        """Threat Intel - Test extrac values from a record based on normalized keys"""
        rec = {
            'account': 12345,
            'region': '123456123456',
            'detail': {
                'eventType': 'AwsConsoleSignIn',
                'eventName': 'ConsoleLogin',
                'userIdentity': {
                    'userName': 'alice',
                    'type': 'Root',
                    'principalId': '12345',
                },
                'sourceIPAddress': '1.1.1.2',
                'recipientAccountId': '12345'
            },
            'source': '1.1.1.2',
            'streamalert:normalization': {
                'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
                'usernNme': [['detail', 'userIdentity', 'userName']]
            },
            'id': '12345'
        }
        result = self.threat_intel._extract_ioc_from_record(rec)
        assert_equal(len(result), 1)
        assert_equal(result[0].value, '1.1.1.2')

    def test_from_config(self):
        """Threat Intel - Test load_config method"""
        test_config = {
            'global': {
                'account': {
                    'region': 'us-east-1'
                },
                'threat_intel': {
                    'dynamodb_table': 'test_table_name',
                    'enabled': True
                }
            }
        }

        threat_intel = StreamThreatIntel.load_from_config(test_config)
        assert_true(isinstance(threat_intel, StreamThreatIntel))

        test_config = {
            'global': {
                'account': {
                    'region': 'us-east-1'
                },
                'threat_intel': {
                    'dynamodb_table': 'test_table_name',
                    'enabled': False
                }
            }
        }
        threat_intel = StreamThreatIntel.load_from_config(test_config)
        assert_false(threat_intel)

        test_config = {
            'types': {
                'log_src1': {
                    'normalizedTypeFoo:ioc_foo': ['foo1', 'foo2'],
                    'normalizedTypeBar:ioc_bar': ['bar1', 'bar2']
                },
                'log_src2': {
                    'normalizedTypePing:ioc_ping': ['ping1', 'ping2'],
                    'normalizedTypePong:ioc_pong': ['pong1', 'pong2']
                }
            }
        }
        StreamThreatIntel.load_from_config(test_config)
        expected_result = {
            'log_src1': {
                'normalizedTypeBar': ['bar1', 'bar2'],
                'normalizedTypeFoo': ['foo1', 'foo2']
            },
            'log_src2': {
                'normalizedTypePing': ['ping1', 'ping2'],
                'normalizedTypePong': ['pong1', 'pong2']
            }
        }
        assert_equal(StreamThreatIntel.normalized_type_mapping(), expected_result)

    def test_process_types_config(self):
        """Threat Intel - Test process_types_config method"""
        test_config = {
            'types': {
                'log_src1': {
                    'normalizedTypeFoo:ioc_foo': ['foo1', 'foo2'],
                    'normalizedTypeBar:ioc_bar': ['bar1', 'bar2'],
                    'normalizedTypePan': ['pan1']
                },
                'log_src2': {
                    'normalizedTypePing:ioc_ping': ['ping1', 'ping2'],
                    'normalizedTypePong:ioc_pong': ['pong1', 'pong2']
                }
            }
        }

        expected_result = {
            'log_src1': {
                'normalizedTypeBar': ['bar1', 'bar2'],
                'normalizedTypeFoo': ['foo1', 'foo2'],
                'normalizedTypePan': ['pan1']
            },
            'log_src2': {
                'normalizedTypePing': ['ping1', 'ping2'],
                'normalizedTypePong': ['pong1', 'pong2']
            }
        }
        StreamThreatIntel._process_types_config(test_config['types'])
        assert_equal(StreamThreatIntel.normalized_type_mapping(), expected_result)

    @patch('stream_alert.rule_processor.threat_intel.LOGGER.info')
    def test_validate_invalid_type_mapping(self, mock_logger):
        """Threat Intel - Test private function to parse invalid types"""
        invalid_str = 'invalidType:ioc_test:foo'
        qualified, normalized_type, ioc_type = self.threat_intel._validate_type_mapping(invalid_str)
        assert_false(qualified)
        assert_equal(normalized_type, None)
        assert_equal(ioc_type, None)
        mock_logger.assert_called_with('Key %s in conf/types.json is incorrect', invalid_str)

    @patch('boto3.client')
    def test_process_ioc(self, mock_client):
        """Threat Intel - Test private method process_ioc"""
        threat_intel = StreamThreatIntel.load_from_config(self.config)
        mock_client('dynamodb').batch_get_item.return_value = MockDynamoDBClient.response()

        ioc_collections = [
            StreamIoc(value='1.1.1.2', ioc_type='ip'),
            StreamIoc(value='2.2.2.2', ioc_type='ip'),
            StreamIoc(value='evil.com', ioc_type='domain')
        ]
        threat_intel._process_ioc(ioc_collections)
        assert_true(ioc_collections[0].is_ioc)
        assert_false(ioc_collections[1].is_ioc)
        assert_true(ioc_collections[2].is_ioc)

    @patch('boto3.client')
    def test_process_ioc_with_unprocessed_keys(self, mock_client):
        """Threat Intel - Test private method process_ioc when response has UnprocessedKeys"""
        threat_intel = StreamThreatIntel.load_from_config(self.config)
        mock_client('dynamodb').batch_get_item.return_value = \
            MockDynamoDBClient.response(unprocesed_keys=True)

        ioc_collections = [
            StreamIoc(value='1.1.1.2', ioc_type='ip'),
            StreamIoc(value='foo', ioc_type='domain'),
            StreamIoc(value='bar', ioc_type='domain')
        ]
        threat_intel._process_ioc(ioc_collections)
        assert_true(ioc_collections[0].is_ioc)
        assert_false(ioc_collections[1].is_ioc)
        assert_false(ioc_collections[2].is_ioc)

    def test_segment(self):
        """Threat Intel - Test _segment method to segment a list to sub-list"""
        # it should only return 1 sub-list when length of list less than MAX_QUERY_CNT (100)
        test_list = [item for item in range(55)]
        result = StreamThreatIntel._segment(test_list)
        assert_equal(len(result), 1)
        assert_equal(len(result[0]), 55)

        # it should return multiple sub-list when len of list more than MAX_QUERY_CNT (100)
        test_list = [item for item in range(345)]
        result = StreamThreatIntel._segment(test_list)
        assert_equal(len(result), 4)
        assert_equal(len(result[0]), 100)
        assert_equal(len(result[1]), 100)
        assert_equal(len(result[2]), 100)
        assert_equal(len(result[3]), 45)

    @patch('boto3.client')
    def test_query(self, mock_client):
        """Threat Intel - Test DynamoDB query method with batch_get_item"""
        threat_intel = StreamThreatIntel.load_from_config(self.config)
        mock_client('dynamodb').batch_get_item.return_value = MockDynamoDBClient.response()

        test_values = ['1.1.1.2', '2.2.2.2', 'evil.com', 'abcdef0123456789']
        result, unprocessed_keys = threat_intel._query(test_values)
        assert_equal(len(result), 2)
        assert_false(unprocessed_keys)
        assert_equal(result[0], {'ioc_value': '1.1.1.2', 'sub_type': 'mal_ip'})
        assert_equal(result[1], {'ioc_value': 'evil.com', 'sub_type': 'c2_domain'})

    @raises(ClientError)
    @patch('boto3.client')
    def test_query_with_exception(self, mock_client):
        """Threat Intel - Test DynamoDB query method with exception"""
        mock_client('dynamodb').batch_get_item.return_value = \
            MockDynamoDBClient.response(exception=True)

        self.threat_intel._query(['1.1.1.2'])

    def test_deserialize(self):
        """Threat Intel - Test method to convert dynamodb types to python types"""
        test_dynamodb_data = [
            {
                'ioc_value': {'S': '1.1.1.2'},
                'sub_type': {'S': 'mal_ip'}
            },
            {
                'test_number': {'N': 10},
                'test_type': {'S': 'test_type'}
            }
        ]

        result = StreamThreatIntel._deserialize(test_dynamodb_data)
        expect_result = [
            {'ioc_value': '1.1.1.2', 'sub_type': 'mal_ip'},
            {'test_number': 10, 'test_type': 'test_type'}
        ]
        assert_equal(result, expect_result)
