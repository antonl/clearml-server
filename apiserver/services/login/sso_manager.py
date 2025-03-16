import re
import uuid
import email_validator
from datetime import datetime
from typing import Dict, Tuple, Any, Optional

from authlib.integrations.flask_client import OAuth
from flask import Flask, url_for, current_app

from apiserver.apierrors import errors
from apiserver.apimodels.auth import CreateUserRequest
from apiserver.bll.auth import AuthBLL
from apiserver.config_repo import config
from apiserver.database import utils as db_utils
from apiserver.database.model.auth import User, Role
from apiserver.database.model.company import Company

log = config.logger(__file__)


class SSOManager:
    """Manages SSO integration with external identity providers using authlib"""
    
    def __init__(self):
        self.oauth = OAuth()
        self.providers = {}
        self._load_providers()
        self.app = None
        
    def _load_providers(self):
        """Load SSO provider configurations from config"""
        self.providers = {}
        if not config.get("auth.sso.enabled", False):
            return
        
        providers_config = config.get("auth.sso.providers", {})
        for provider_id, provider_config in providers_config.items():
            self.providers[provider_id] = provider_config
            
    def init_app(self, app: Flask):
        """Initialize OAuth client with Flask app"""
        self.app = app
        self.oauth.init_app(app)
        
        # Register OAuth clients for each provider
        for provider_id, provider_config in self.providers.items():
            # Different registration based on provider type
            if "server_metadata_url" in provider_config:
                # OpenID Connect provider
                self.oauth.register(
                    name=provider_id,
                    client_id=provider_config.get("client_id"),
                    client_secret=provider_config.get("client_secret"),
                    server_metadata_url=provider_config.get("server_metadata_url"),
                    client_kwargs=provider_config.get("client_kwargs", {}),
                )
            else:
                # OAuth2 provider
                self.oauth.register(
                    name=provider_id,
                    client_id=provider_config.get("client_id"),
                    client_secret=provider_config.get("client_secret"),
                    authorize_url=provider_config.get("authorize_url"),
                    token_url=provider_config.get("token_url"),
                    userinfo_url=provider_config.get("userinfo_url"),
                    client_kwargs=provider_config.get("client_kwargs", {}),
                )
    
    def get_providers(self) -> Dict[str, Dict]:
        """Get available SSO providers"""
        return self.providers
    
    def get_authorization_url(self, provider_id: str, state: Optional[str] = None, callback_url_prefix: Optional[str] = None) -> str:
        """Generate authorization URL for the specified provider"""
        if provider_id not in self.providers:
            raise errors.bad_request.InvalidId(f"Unknown SSO provider: {provider_id}")
        
        # Generate state if not provided
        if not state:
            state = str(uuid.uuid4())
            
        # Determine callback URL
        callback_url = config.get("auth.sso.callback_url")
        if callback_url_prefix:
            # Use user-provided callback URL prefix if provided
            callback_url = f"{callback_url_prefix}/auth/sso/callback"
        
        # Create redirect URL
        with self.app.test_request_context('/'):
            client = self.oauth.create_client(provider_id)
            return client.authorize_redirect(callback_url, state=state)
            
    def process_callback(self, provider: str, code: str, state: Optional[str] = None, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
        """Process OAuth callback and get user info from the provider"""
        if provider not in self.providers:
            raise errors.bad_request.InvalidId(f"Unknown SSO provider: {provider}")
        
        with self.app.test_request_context('/'):
            client = self.oauth.create_client(provider)
            
            # Exchange authorization code for token
            token = client.fetch_token(
                code=code, 
                redirect_uri=redirect_uri or config.get("auth.sso.callback_url"),
                state=state
            )
            
            # Get user info
            user_info = client.userinfo(token=token)
            
            # For GitHub, sometimes email is not included in the userinfo response
            # Need to make an additional call to get emails
            if provider == 'github' and 'email' not in user_info and hasattr(client, 'get'):
                provider_config = self.providers.get(provider, {})
                email_url = provider_config.get('userinfo_email_url')
                if email_url:
                    resp = client.get(email_url, token=token)
                    if resp.status_code == 200:
                        emails = resp.json()
                        # Find the primary email or use the first one
                        primary_email = next((e for e in emails if e.get('primary')), emails[0] if emails else None)
                        if primary_email:
                            user_info['email'] = primary_email.get('email')
            
            return user_info
    
    def get_or_create_user(self, user_info: Dict[str, Any]) -> Tuple[str, str]:
        """
        Create or get a user from the database based on SSO information
        Returns: (user_id, company_id)
        """
        # Extract email from user info
        email = user_info.get('email')
        if not email:
            raise errors.bad_request.ValidationError("Email not provided by identity provider")
        
        try:
            # Normalize the email
            email_info = email_validator.validate_email(email, check_deliverability=False)
            email = email_info.normalized
        except email_validator.EmailNotValidError:
            raise errors.bad_request.ValidationError(f"Invalid email address: {email}")
        
        # Check if user already exists
        user = User.objects(email=email).first()
        if user:
            return user.id, user.company
        
        # User doesn't exist, need to create one
        name = user_info.get('name') or user_info.get('display_name') or email.split('@')[0]
        email_domain = email.split('@')[1]
        
        # Check for existing company based on email domain
        company = Company.objects(id__contains=email_domain).first()
        
        # If no company exists, check if we should auto-create one
        if not company and config.get("auth.sso.auto_create_company", False):
            company_name = config.get("auth.sso.default_company_name_pattern", "{email_domain} Organization")
            company_name = company_name.format(email_domain=email_domain, user_name=name)
            
            # Create new company
            company_id = db_utils.id()
            company = Company(id=company_id, name=company_name)
            company.save()
        elif not company:
            raise errors.bad_request.ValidationError(
                f"No company found for domain '{email_domain}' and auto-create is disabled"
            )
        
        # Determine role - check if this is the first user in the company
        role = Role.user  # Default role
        
        # Make the first user an admin if configured
        user_count = User.objects(company=company.id).count()
        if user_count == 0 and config.get("auth.sso.first_user_is_admin", False):
            role = Role.admin
        else:
            # Use default role from config
            role = config.get("auth.sso.default_role", Role.user)
        
        # Parse name into given_name and family_name (best effort)
        name_parts = name.split()
        given_name = name_parts[0] if name_parts else ""
        family_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else ""
        
        # Create user using AuthBLL to ensure proper creation in both auth and backend
        try:
            # Create user request
            create_request = CreateUserRequest(
                name=name,
                company=company.id,
                email=email,
                role=role,
                given_name=given_name,
                family_name=family_name,
                avatar=user_info.get("picture")
            )
            
            # Create the user
            user_id = AuthBLL.create_user(request=create_request)
            
            return user_id, company.id
        except Exception as e:
            log.error(f"Failed to create user from SSO: {str(e)}")
            raise errors.server_error.GeneralError(
                "Failed to create user from SSO login",
                ex=str(e)
            )


# Create a singleton instance
sso_manager = SSOManager()