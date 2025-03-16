from apiserver.apimodels.login import (
    GetSupportedModesRequest,
    GetSupportedModesResponse,
    BasicMode,
    BasicGuestMode,
    ServerErrors,
    SSOLoginRequest,
)
from apiserver.apimodels.auth import GetTokenResponse
from apiserver.config import info
from apiserver.service_repo import endpoint, APICall
from apiserver.service_repo.auth import revoke_auth_token
from apiserver.service_repo.auth.fixed_user import FixedUser
from apiserver.bll.auth import AuthBLL
from apiserver.config_repo import config

from .sso_manager import sso_manager

log = config.logger(__file__)


@endpoint("login.supported_modes", response_data_model=GetSupportedModesResponse)
def supported_modes(call: APICall, company_id: str, request: GetSupportedModesRequest):
    guest_user = FixedUser.get_guest_user()
    if guest_user:
        guest = BasicGuestMode(
            enabled=True,
            name=guest_user.name,
            username=guest_user.username,
            password=guest_user.password,
        )
    else:
        guest = BasicGuestMode()

    # Get configured SSO providers
    sso_enabled = config.get("auth.sso.enabled", False)
    sso_providers = []
    sso_urls = {}

    if sso_enabled:
        providers = sso_manager.get_providers()
        for provider_id, provider_info in providers.items():
            # Generate authorization URL for this provider
            auth_url = sso_manager.get_authorization_url(
                provider_id, 
                state=request.state,
                callback_url_prefix=request.callback_url_prefix
            )
            
            sso_providers.append({
                "id": provider_id,
                "name": provider_info.get("name", provider_id.capitalize())
            })
            
            sso_urls[provider_id] = auth_url

    return GetSupportedModesResponse(
        basic=BasicMode(enabled=FixedUser.enabled(), guest=guest),
        sso=sso_urls,
        sso_providers=sso_providers,
        server_errors=ServerErrors(
            missed_es_upgrade=info.missed_es_upgrade,
            es_connection_error=info.es_connection_error,
        ),
        authenticated=call.auth is not None,
    )


@endpoint("login.logout", min_version="2.13")
def logout(call: APICall, company_id: str, request):
    revoke_auth_token(call.auth)
    call.result.set_auth_cookie(None)


@endpoint("login.sso_login", request_data_model=SSOLoginRequest, response_data_model=GetTokenResponse)
def sso_login(call: APICall, company_id: str, request: SSOLoginRequest):
    """Handle OAuth/OIDC authorization code callback from the frontend"""
    # Get user info from the OAuth provider
    user_info = sso_manager.process_callback(
        provider=request.provider,
        code=request.code,
        state=request.state,
        redirect_uri=request.redirect_uri
    )
    
    # Create or get the user from the database
    user_id, company_id = sso_manager.get_or_create_user(user_info)
    
    # Generate token for the user
    token_response = AuthBLL.get_token_for_user(
        user_id=user_id, 
        company_id=company_id
    )
    
    # Set the auth cookie
    call.result.set_auth_cookie(token_response.token)
    
    return token_response
