<?php

namespace App\Security;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\AudienceChecker;
use Psr\Clock\ClockInterface;

class IdTokenValidator
{
    public function __construct(
        private ClockInterface $clock,
        private string $issuer,
        private string $clientId,
        private string $jwksUri,
    ) {}

    public function validate(string $idToken, string $expectedNonce): array
    {
        // Load keys from JWKS endpoint
        $jwkSet = JWKSet::createFromJson(file_get_contents($this->jwksUri));

        // Build managers
        $algorithmManager = new AlgorithmManager([new RS256()]);
        $verifier = new JWSVerifier($algorithmManager);

        $serializerManager = new JWSSerializerManager([new CompactSerializer()]);

        // Loader with serializer + verifier
        $loader = new JWSLoader($serializerManager, $verifier, null);

        // Verify signature
        $jws = $loader->loadAndVerifyWithKeySet($idToken, $jwkSet, $signatureIndex);
        if (!$jws) {
            throw new \RuntimeException('Unable to verify ID token signature');
        }

        // Parse claims
        $claims = json_decode($jws->getPayload(), true, 512, JSON_THROW_ON_ERROR);

        // Standard OIDC claim checks
        $checker = new ClaimCheckerManager([
            new IssuedAtChecker($this->clock, 60),
            new NotBeforeChecker($this->clock, 60),
            new ExpirationTimeChecker($this->clock, 60),
            new IssuerChecker([$this->issuer]),
            new AudienceChecker($this->clientId),
        ]);
        $checker->check($claims, ['iat', 'exp', 'iss', 'aud']);

        // Nonce check
        if (!isset($claims['nonce']) || $claims['nonce'] !== $expectedNonce) {
            throw new \RuntimeException('Invalid nonce in ID token');
        }

        return $claims;
    }
}
