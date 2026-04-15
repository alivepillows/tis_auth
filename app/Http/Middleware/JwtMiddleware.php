<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use App\Models\User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;

class JwtMiddleware
{
    public function handle($request, Closure $next)
    {
        $token = $request->header('token') ?? $request->query('token');
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'token not provided'
            ], 401);
        }
        try {
            $credentials = JWT::decode($token, new Key(env('JWT_SECRET'), 'HS256'));
        } catch (ExpiredException $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'token expired'
            ], 400);
        } catch (Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'invalid token'
            ], 400);
        }
        $user = User::find($credentials->sub);
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
