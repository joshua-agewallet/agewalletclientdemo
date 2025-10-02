<?php

namespace App\Controller;

use App\Security\IdTokenValidator;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class AgeWalletController extends AbstractController
{
    #[Route('/connect/agewallet', name: 'connect_agewallet_start')]
    public function connect(ClientRegistry $clientRegistry, Request $request): RedirectResponse
    {
        $nonce = bin2hex(random_bytes(16));

        // Generate PKCE verifier & challenge
        $verifier = bin2hex(random_bytes(64));
        $challenge = rtrim(
            strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'),
            '='
        );

        $session = $request->getSession();
        $session->set('oidc_nonce', $nonce);
        $session->set('pkce_verifier', $verifier);

        return $clientRegistry->getClient('agewallet')->redirect(
            ['openid age'],
            [
                'nonce' => $nonce,
                'code_challenge' => $challenge,
                'code_challenge_method' => 'S256',
            ]
        );
    }

    #[Route('/connect/agewallet/check', name: 'connect_agewallet_check')]
    public function connectCheck(Request $request, ClientRegistry $clientRegistry, IdTokenValidator $idTokenValidator)
    {
        $client = $clientRegistry->getClient('agewallet');

        // Exchange code for tokens (with PKCE verifier)
        $accessToken = $client->getAccessToken([
            'code_verifier' => $request->getSession()->get('pkce_verifier'),
        ]);

        // Extract raw ID token
        $idToken = $accessToken->getValues()['id_token'] ?? null;
        if (!$idToken) {
            throw new \RuntimeException('Missing ID token in response');
        }

        // Validate ID token
        $claims = $idTokenValidator->validate(
            $idToken,
            $request->getSession()->get('oidc_nonce') // expected nonce
        );

        // At this point, claims are trusted
        // e.g. create user session, redirect, etc.
        return $this->json([
            'access_token' => $accessToken->getToken(),
            'id_token' => $idToken,
            'claims' => $claims,
        ]);
    }



}
