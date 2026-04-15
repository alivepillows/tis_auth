<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class HomeController extends Controller
{
    public function home(Request $request)
    {
        $user = $request->user;
        return response()->json([
            'status' => 'success',
            'message' => 'selamat datang ' . $user->name
        ], 200);
    }
}
