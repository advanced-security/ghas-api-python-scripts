"""Test TLS certificate bundle support in githubapi module."""

import pytest
from unittest.mock import patch, MagicMock
import os


def test_github_verify_default():
    """Test that GitHub class defaults to verify=True."""
    with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
        with patch("githubapi.requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            
            from githubapi import GitHub
            
            _gh = GitHub()
            
            # Verify that session.verify is set to True by default
            assert mock_session.verify == True


def test_github_verify_false():
    """Test that GitHub class accepts verify=False."""
    with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
        with patch("githubapi.requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            
            from githubapi import GitHub
            
            _gh = GitHub(verify=False)
            
            # Verify that session.verify is set to False
            assert mock_session.verify == False


def test_github_verify_cert_bundle():
    """Test that GitHub class accepts verify with certificate bundle path."""
    with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
        with patch("githubapi.requests.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            
            from githubapi import GitHub
            
            cert_path = "/path/to/cert.pem"
            _gh = GitHub(verify=cert_path)
            
            # Verify that session.verify is set to the certificate path
            assert mock_session.verify == cert_path


def test_github_token_required():
    """Test that GitHub class requires a token."""
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="GITHUB_TOKEN environment variable must be set"):
            from githubapi import GitHub
            _gh = GitHub()


def test_github_hostname_validation():
    """Test that GitHub class validates hostname."""
    with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
        with pytest.raises(ValueError, match="Invalid server hostname"):
            from githubapi import GitHub
            _gh = GitHub(hostname="invalid hostname with spaces")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
