<?php

namespace bgamrat\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use bgamrat\OAuth2\Client\Provider\CanvasLMSResourceOwner;

class CanvasLMS extends AbstractProvider {

    use ArrayAccessorTrait,
        BearerAuthorizationTrait;

    /**
     * URL of Canvas Instance (e.g. https://canvas.instructure.com)
     * @var string
     */
    protected $canvasInstanceUrl;

    /**
     * Human-readable purpose for which API access token will be issued
     * @var string
     */
    protected $purpose;

    /**
     * Type of token requested (`authorization_code` or `refresh_token`)
     * @var [type]
     */
    protected $grantType;
    /* TODO https://github.com/smtech/oauth2-canvaslms/issues/1 */
    protected $scopes = [];

    protected function getAuthorizationParameters(array $options) {
        $options = parent::getAuthorizationParameters($options);
        $options['purpose'] = $this->purpose;
        return $options;
    }

    public function getBaseAuthorizationUrl() {
        return "{$this->canvasInstanceUrl}/login/oauth2/auth";
    }

    public function getBaseAccessTokenUrl(array $params) {
        return "{$this->canvasInstanceUrl}/login/oauth2/token";
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token = null) {
        return "{$this->canvasInstanceUrl}/api/v1/users/self/profile";
    }

    public function getDefaultScopes() {
        return $this->scopes;
    }

    public function checkResponse(ResponseInterface $response, $data) {
        if (!empty($data['error'])) {
            throw new IdentityProviderException($data['error_description'], $response->getStatusCode(), $response);
        }
    }

    public function createResourceOwner(array $response, AccessToken $token = null) {
        return new CanvasLMSResourceOwner($response);
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(AccessToken $token = null) {
        $response = $this->fetchResourceOwnerDetails($token);
        return $this->createResourceOwner($response, $token);
    }

    /**
     * Requests resource owner details.
     *
     * @param  AccessToken $token
     * @return mixed
     */
    protected function fetchResourceOwnerDetails(AccessToken $token = null) {
        $url = $this->getResourceOwnerDetailsUrl($token);
        $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);
        $response = $this->getParsedResponse($request);
        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                            'Invalid response received from Authorization Server. Expected JSON.'
            );
        }
        return $response;
    }

    public function getAccessTokenRequest(array $params = []) {
        $request = parent::getAccessTokenRequest($params);
        $uri = $request->getUri()->withUserInfo($this->clientId, $this->clientSecret);
        return $request->withUri($uri);
    }

    /**
     * Requests a bearer token using a specified grant and option set.
     *
     * @param  mixed $grant
     * @param  array $options
     * @throws IdentityProviderException
     * @return mixed $token or AccessTokenInterface
     */
    public function getAccessToken($grant, array $options = []) {
        $grant = $this->verifyGrant($grant);

        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
        ];

        $params = $grant->prepareRequestParameters($params, $options);

        $request = $this->getAccessTokenRequest($params);

        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                            'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        $token = $response['access_token'];
        if ($response['access_token'] !== null) {
            $prepared = $this->prepareAccessTokenResponse($response);

            $token = $this->createAccessToken($prepared, $grant);
        }
        return $token;
    }

    protected function getScopeSeparator() {
        if (!isset($this->scopeSeparator)) {
            $this->scopeSeparator = ' ';
        }
        return $this->scopeSeparator;
    }

}
