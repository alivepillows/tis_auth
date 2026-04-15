<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;

class Authorization
{
    private function base64url_encode($data)
    {
        $base64 = base64_encode($data);
        return rtrim(strtr($base64, '+/', '-_'), '=');
    }
    private function base64url_decode($data)
    {
        $base64 = strtr($data, '-_', '+/');
        return base64_decode($base64);
    }
    private function sign($header, $payload, $secret)
    {
        $signature = hash_hmac('sha256', "$header.$payload", $secret, true);
        return $this->base64url_encode($signature);
    }
    private function verify($signature, $header, $payload, $secret)
    {
        $expected = $this->sign($header, $payload, $secret);
        return hash_equals($expected, $signature);
    }
    public function handle($request, Closure $next)
    {
        $token = $request->header('token') ?? $request->query('token');
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'token not provided'
            ], 400);
        }
        [$header, $payload, $signature] = explode('.', $token);
        $header_json = json_decode($this->base64url_decode($header));
        $payload_json = json_decode($this->base64url_decode($payload));
        if (!$header_json || $header_json->alg !== 'HS256' || $header_json->typ !== 'JWT') {
            return response()->json([
                'status' => 'error',
                'message' => 'invalid token header'
            ], 401);
        }
        if (!$payload_json || !isset($payload_json->id)) {
            return response()->json([
                'status' => 'error',
                'message' => 'invalid payload'
            ], 400);
        }
        $isValid = $this->verify($signature, $header, $payload, 'secret');
        if (!$isValid) {
            return response()->json([
                'status' => 'error',
                'message' => 'invalid signature'
            ], 401);
        }
        $user = User::find($payload_json->id);
        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'user not found'
            ], 404);
        }
        $request->user = $user;
        return $next($request);
    }
}
