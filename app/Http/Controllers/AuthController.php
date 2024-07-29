<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\PersonalAccessTokenResult;

class AuthController extends Controller
{
    // Other methods...

    public function register(Request $request)
    {
        $request->validate([
            'first_name' => 'required|string|max:255',
            'last_name' => 'required|string|max:255',
            'email' => 'nullable|email|max:255|unique:users',
            'phone_number' => 'nullable|string|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $user = User::create([
            'first_name' => $request->input('first_name'),
            'last_name' => $request->input('last_name'),
            'email' => $request->input('email'),
            'phone_number' => $request->input('phone_number'),
            'password' => Hash::make($request->input('password')),
        ]);

        // Create a personal access token
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->accessToken;

        return response()->json([
            'message' => 'User registered successfully.',
            'token' => $token
        ]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required_without:phone_number|email',
            'phone_number' => 'required_without:email',
            'password' => 'required|string',
        ]);

        $credentials = $request->only(['email', 'phone_number', 'password']);
        $field = filter_var($request->input('email'), FILTER_VALIDATE_EMAIL) ? 'email' : 'phone_number';

        if (Auth::attempt([$field => $credentials[$field], 'password' => $credentials['password']])) {
            $user = Auth::user();
            $tokenResult = $user->createToken('Personal Access Token');
            $token = $tokenResult->accessToken;

            return response()->json([
                'message' => 'Login successful.',
                'token' => $token
            ]);
        } else {
            return response()->json(['message' => 'Unauthorized'], 401);
        }
    }
}