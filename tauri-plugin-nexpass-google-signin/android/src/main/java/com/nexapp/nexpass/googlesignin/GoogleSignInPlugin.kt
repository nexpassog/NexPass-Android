package com.nexapp.nexpass.googlesignin

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.util.Log
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultCallback
import androidx.activity.result.contract.ActivityResultContracts
import com.google.android.gms.auth.api.identity.BeginSignInRequest
import com.google.android.gms.auth.api.identity.BeginSignInResult
import com.google.android.gms.auth.api.identity.Identity
import com.google.android.gms.auth.api.identity.SignInClient
import com.google.android.gms.auth.api.identity.SignInCredential
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.tasks.OnCompleteListener
import com.google.android.gms.tasks.Task
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Permission
import org.json.JSONObject

@TauriPlugin
class GoogleSignInPlugin(private val activity: Activity) : Plugin(activity) {

    private var signInClient: SignInClient? = null
    private var googleSignInClient: GoogleSignInClient? = null
    private var pendingInvoke: Invoke? = null
    private val signInRequestCode = 9001

    override fun onCreate() {
        super.onCreate()
        
        // Initialize Google Identity Services (One Tap / Credential Manager)
        signInClient = Identity.getSignInClient(activity)
        
        // Also initialize legacy GoogleSignInClient for server auth code
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken(activity.getString(com.nexapp.nexpass.googlesignin.R.string.default_web_client_id))
            .requestServerAuthCode(activity.getString(com.nexapp.nexpass.googlesignin.R.string.default_web_client_id), true)
            .requestEmail()
            .requestProfile()
            .build()
        googleSignInClient = GoogleSignIn.getClient(activity, gso)
    }

    @Command
    fun isAvailable(invoke: Invoke) {
        val result = JSObject()
        val available = signInClient != null
        result.put("available", available)
        invoke.resolve(result)
    }

    @Command
    fun signIn(invoke: Invoke) {
        pendingInvoke = invoke
        
        // Use Google Identity Services BeginSignInRequest for native account picker
        val beginSignInRequest = BeginSignInRequest.builder()
            .setGoogleIdTokenRequestOptions(
                BeginSignInRequest.GoogleIdTokenRequestOptions.builder()
                    .setSupported(true)
                    .setServerClientId(activity.getString(com.nexapp.nexpass.googlesignin.R.string.default_web_client_id))
                    .setFilterByAuthorizedAccounts(false)
                    .build()
            )
            .build()

        signInClient?.beginSignIn(beginSignInRequest)
            ?.addOnSuccessListener { result: BeginSignInResult ->
                try {
                    // Launch the native account picker
                    val intentSender = result.pendingIntent.intentSender
                    activity.startIntentSenderForResult(
                        intentSender,
                        signInRequestCode,
                        null, 0, 0, 0, null
                    )
                } catch (e: IntentSender.SendIntentException) {
                    Log.e("GoogleSignInPlugin", "Failed to start sign-in intent", e)
                    val errorResult = JSObject()
                    errorResult.put("error", "Failed to start sign-in: ${e.message}")
                    invoke.reject(errorResult.toString())
                    pendingInvoke = null
                }
            }
            ?.addOnFailureListener { e ->
                Log.e("GoogleSignInPlugin", "Begin sign-in failed", e)
                val errorResult = JSObject()
                errorResult.put("error", "Begin sign-in failed: ${e.message}")
                invoke.reject(errorResult.toString())
                pendingInvoke = null
            }
    }

    @Command
    fun signOut(invoke: Invoke) {
        // Sign out from Google Identity Services
        signInClient?.signOut()
            ?.addOnCompleteListener { _ ->
                // Also sign out from legacy client
                googleSignInClient?.signOut()
                val result = JSObject()
                invoke.resolve(result)
            }
            ?.addOnFailureListener { e ->
                Log.e("GoogleSignInPlugin", "Sign out failed", e)
                val result = JSObject()
                result.put("error", e.message)
                invoke.reject(result.toString())
            }
    }

    @Command
    fun getCurrentUser(invoke: Invoke) {
        // Check if there's a saved account from Google Identity Services
        val account = GoogleSignIn.getLastSignedInAccount(activity)
        
        val result = JSObject()
        if (account != null) {
            val userJson = accountToJson(account)
            result.put("user", userJson)
        } else {
            result.put("user", JSONObject())
        }
        invoke.resolve(result)
    }

    private fun accountToJson(account: GoogleSignInAccount): JSONObject {
        val json = JSONObject()
        json.put("id", account.id)
        json.put("email", account.email)
        json.put("displayName", account.displayName)
        json.put("givenName", account.givenName)
        json.put("familyName", account.familyName)
        json.put("photoUrl", account.photoUrl?.toString())
        json.put("idToken", account.idToken)
        json.put("serverAuthCode", account.serverAuthCode)
        return json
    }

    // Handle the activity result from the sign-in intent
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == signInRequestCode) {
            val invoke = pendingInvoke ?: return
            pendingInvoke = null
            
            if (resultCode == Activity.RESULT_OK) {
                // Get the sign-in credential from the result
                try {
                    val credential = Identity.getSignInClient(activity)
                        .getSignInCredentialFromIntent(data!!)
                    
                    val googleIdToken = credential.googleIdToken
                    
                    if (googleIdToken != null) {
                        // Also get the legacy account for server auth code
                        val task = GoogleSignIn.getSignedInAccountFromIntent(data)
                        task.addOnCompleteListener { signInTask ->
                            try {
                                val account = signInTask.getResult(ApiException::class.java)
                                
                                val result = JSObject()
                                val userJson = if (account != null) {
                                    accountToJson(account)
                                } else {
                                    // Fallback to just the ID token info
                                    val fallbackJson = JSONObject()
                                    fallbackJson.put("idToken", googleIdToken)
                                    fallbackJson.put("id", "")
                                    fallbackJson.put("email", "")
                                    fallbackJson
                                }
                                result.put("user", userJson)
                                invoke.resolve(result)
                            } catch (e: ApiException) {
                                Log.e("GoogleSignInPlugin", "Sign-in failed", e)
                                val errorResult = JSObject()
                                errorResult.put("error", "Sign-in failed: ${e.statusCode} - ${e.message}")
                                invoke.reject(errorResult.toString())
                            }
                        }
                    } else {
                        val errorResult = JSObject()
                        errorResult.put("error", "No ID token received")
                        invoke.reject(errorResult.toString())
                    }
                } catch (e: ApiException) {
                    Log.e("GoogleSignInPlugin", "Failed to get credential", e)
                    val errorResult = JSObject()
                    errorResult.put("error", "Failed to get credential: ${e.statusCode} - ${e.message}")
                    invoke.reject(errorResult.toString())
                }
            } else if (resultCode == Activity.RESULT_CANCELED) {
                val errorResult = JSObject()
                errorResult.put("error", "Sign-in cancelled by user")
                invoke.reject(errorResult.toString())
            } else {
                val errorResult = JSObject()
                errorResult.put("error", "Sign-in failed with result code: $resultCode")
                invoke.reject(errorResult.toString())
            }
        }
    }
}