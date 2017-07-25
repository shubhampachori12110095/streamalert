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
from mock import patch

from botocore.exceptions import ClientError

from stream_alert.rule_processor.metrics import put_metric_data, _put_metric


@patch('logging.Logger.error')
def test_invalid_metric_name(log_mock):
    """Metrics - Invalid Name"""
    put_metric_data('bad metric name', 100, 'Seconds')

    log_mock.assert_called_with('Metric name not defined: %s', 'bad metric name')


@patch('logging.Logger.error')
def test_invalid_metric_unit(log_mock):
    """Metrics - Invalid Unit Type"""
    put_metric_data('RuleProcessorFailedParses', 100, 'Total')

    log_mock.assert_called_with('Metric unit not defined: %s', 'Total')


@patch('stream_alert.rule_processor.metrics._put_metric')
def test_valid_metric(metric_mock):
    """Metrics - Valid Metric"""
    put_metric_data('RuleProcessorFailedParses', 100, 'Count')

    metric_mock.assert_called()


@patch('stream_alert.rule_processor.metrics.BOTO_CW_CLIENT.put_metric_data')
def test_boto_call(boto_mock):
    """Metrics - Boto Call Params"""

    _put_metric([{'test': 'info'}])
    boto_mock.assert_called_with(Namespace='StreamAlert', MetricData=[{'test': 'info'}])


@patch('stream_alert.rule_processor.metrics.BOTO_CW_CLIENT.put_metric_data')
@patch('logging.Logger.exception')
def test_boto_failed(log_mock, boto_mock):
    """Metrics - Boto Call Failed"""

    err_response = {
        'Error':
            {
                'Code': 100,
                'Message': 'BAAAD',
                'BucketName': 'bucket'
            }
    }

    # Add ClientError side_effect to mock
    boto_mock.side_effect = ClientError(err_response, 'operation')

    _put_metric([{'test': 'info'}])

    log_mock.assert_called_with('Failed to send metric to CloudWatch. Error: %s\nMetric data:\n%s',
                                err_response,
                                '[\n  {\n    "test": "info"\n  }\n]')
