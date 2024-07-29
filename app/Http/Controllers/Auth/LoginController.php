<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    public function showLoginForm()
    {
        return view('auth.login');
    }

    public function login(Request $request)
    {
        $request->validate([
            'login' => 'required',
            'password' => 'required',
        ]);

        $credentials = ['password' => $request->input('password')];

        // Check for email or phone number
        if (filter_var($request->input('login'), FILTER_VALIDATE_EMAIL)) {
            $credentials['email'] = $request->input('login');
        } else {
            $credentials['phone_number'] = $request->input('login');
        }

        if (Auth::attempt($credentials)) {
            return redirect()->intended('home');
        }

        return redirect()->back()->withErrors(['login' => 'Invalid credentials'])->withInput();
    }
}
