import pytest
from unittest.mock import patch, MagicMock, call
from resolve_duplicate_secret_scanning_alerts import main

import argparse
import logging


# logging.getLogger("resolve_duplicate_secret_scanning_alerts").setLevel(logging.DEBUG)


@pytest.fixture
def mock_args():
    with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
        mock_parse_args.return_value = argparse.Namespace(
            name="test_org",
            scope="org",
            state="open",
            since="2024-10-08",
            hostname="github.com",
            debug=True,
            add_matching_secret=[("old_type", "new_type")]
        )
        yield mock_parse_args

@pytest.fixture
def mock_github():
    with patch('resolve_duplicate_secret_scanning_alerts.GitHub') as mock_github:
        yield mock_github

@pytest.fixture
def mock_list_secret_scanning_alerts():
    with patch('resolve_duplicate_secret_scanning_alerts.list_secret_scanning_alerts') as mock_list:
        mock_list.return_value = [
            {"repo": "test_org/test_repo", "secret_type": "old_type", "secret": "secret1", "state": "resolved", "url": "https://github.com/test_org/test_repo/1", "resolution": "false_positive", "resolution_comment": "Foo" },
            {"repo": "test_org/test_repo", "secret_type": "new_type", "secret": "secret1", "state": "open", "url": "https://github.com/test_org/test_repo/2", "resolution": None, "resolution_comment": None },
            {"repo": "test_org/test_repo", "secret_type": "google_cloud_private_key_id", "secret": "1234567", "state": "resolved", "url": "https://github.com/test_org/test_repo/3", "resolution": "false_positive", "resolution_comment": "Foo" },
            {"repo": "test_org/test_repo", "secret_type": "google_cloud_service_account_credentials", "secret": '{"private_key_id": "1234567"}', "state": "open", "url": "https://github.com/test_org/test_repo/4", "resolution": None, "resolution_comment": None },
        
        ]
        yield mock_list

def test_main(mock_args, mock_github, mock_list_secret_scanning_alerts):
    mock_github_instance = mock_github.return_value
    mock_github_instance.query_once = MagicMock()

    main()

    mock_github_instance.query_once.assert_has_calls(
        [
            call(
                "repo",
                "test_org/test_repo",
                "/secret-scanning/alerts/2",
                data={
                    "state": "resolved",
                    "resolution": "false_positive",
                    "resolution_comment": "Foo"
                },
                method="PATCH"
            ),
            call(
                "repo",
                "test_org/test_repo",
                "/secret-scanning/alerts/4",
                data={
                    "state": "resolved",
                    "resolution": "false_positive",
                    "resolution_comment": "Foo"
                },
                method="PATCH"
            ),
        ],
        any_order=True
    )
    assert mock_github_instance.query_once.call_count == 2
