<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Firebase\JWT\JWT;



class AuthController extends Controller
{
    public function register(Request $request)
    {
        $name = $request->name;
        $email = $request->email;
        $password = Hash::make($request->password);
        $user = User::create([
            'name' => $name,
            'email' => $email,
            'password' => $password
        ]);
        return response()->json([
            'status' => 'success',
            'message' => 'user created',
            'data' => $user
        ], 201);
    }

    public function login(Request $request)
    {
        $email = $request->email;
        $password = $request->password;
        $user = User::where('email', $email)->first();
        if (!$user) {
            return response()->json([
                'status' => 'error',
                'message' => 'user not found'
            ], 404);
        }
        if (!Hash::check($password, $user->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'wrong password'
            ], 400);
        }
        $user->token = $this->jwt($user);
        $user->save();
        return response()->json([
            'status' => 'success',
            'message' => 'login success',
            'data' => $user
        ], 200);
    }



    private function base64url_encode($data)
    {
        $base64 = base64_encode($data);
        $base64url = strtr($base64, '+/', '-_');
        return rtrim($base64url, '=');
    }

    private function sign($header, $payload, $secret)
    {
        $signature = hash_hmac('sha256', "$header.$payload", $secret, true);
        return $this->base64url_encode($signature);
    }

    // private function jwt($header, $payload, $secret)
    // {
    //     $header_json = json_encode($header);
    //     $payload_json = json_encode($payload);
    //     $header_base64 = $this->base64url_encode($header_json);
    //     $payload_base64 = $this->base64url_encode($payload_json);
    //     $signature = $this->sign($header_base64, $payload_base64, $secret);
    //     return "$header_base64.$payload_base64.$signature";
    // }
    protected function jwt($user)
    {
        $payload = [
            'iss' => 'laravel-jwt',
            'sub' => $user->id,
            'iat' => time(),
            'exp' => time() + 60 * 60
        ];
        return JWT::encode($payload, env('JWT_SECRET'), 'HS256');
    }
}
