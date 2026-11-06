
/* ============================================================
   BUSINESSOS — CENTRAL AUTHENTICATION & IDENTITY SERVICE
   Firebase Project: business-os-by

   Responsibilities:
   - Firebase initialization
   - Email/password registration and login
   - Google authentication
   - Email verification
   - Password recovery and reset
   - Persistent authentication state
   - User profile creation and synchronization
   - Firebase UID identity
   - Referral and invitation attribution
   - Business registration and membership
   - Business role checks
   - Phone verification integration point
   - Authentication guards
   - Splash-screen routing

   IMPORTANT:
   Privileged operations, OTP generation, referral rewards,
   role elevation and administrative permissions require a
   trusted backend and Firestore Security Rules.
============================================================ */


/* ============================================================
   1. FIREBASE SDK IMPORTS
============================================================ */

import {
    initializeApp,
    getApps,
    getApp
} from "https://www.gstatic.com/firebasejs/13.2.0/firebase-app.js";


import {
    getAuth,
    setPersistence,
    browserLocalPersistence,
    onAuthStateChanged,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    GoogleAuthProvider,
    signInWithPopup,
    signInWithRedirect,
    getRedirectResult,
    signOut,
    sendEmailVerification,
    sendPasswordResetEmail,
    confirmPasswordReset,
    updateProfile as firebaseUpdateProfile,
    updateEmail,
    updatePassword,
    EmailAuthProvider,
    reauthenticateWithCredential,
    reload,
    getIdToken
} from "https://www.gstatic.com/firebasejs/13.2.0/firebase-auth.js";


import {
    getFirestore,
    doc,
    collection,
    getDoc,
    getDocs,
    setDoc,
    updateDoc,
    runTransaction,
    serverTimestamp
} from "https://www.gstatic.com/firebasejs/13.2.0/firebase-firestore.js";


/* ============================================================
   2. FIREBASE PROJECT CONFIGURATION
============================================================ */

const firebaseConfig = {

    apiKey: "AIzaSyCaItsHbMSCA-jKJ5IldpRD0NEW_M9eJ68",

    authDomain: "business-os-by.firebaseapp.com",

    projectId: "business-os-by",

    storageBucket: "business-os-by.firebasestorage.app",

    messagingSenderId: "970110196253",

    appId: "1:970110196253:web:c7f9f4472f6e084c5544f4",

    measurementId: "G-KBGYD6D73L"

};


/* ============================================================
   3. INITIALIZE FIREBASE
============================================================ */

export const app = getApps().length
    ? getApp()
    : initializeApp(firebaseConfig);


export const auth = getAuth(app);

export const db = getFirestore(app);


/* ============================================================
   4. AUTHENTICATION PERSISTENCE
============================================================ */

export const persistenceReady = setPersistence(
    auth,
    browserLocalPersistence
).catch((error) => {

    console.warn(
        "Session persistence could not be configured:",
        error
    );

    return null;

});


/* ============================================================
   5. GOOGLE AUTHENTICATION PROVIDER
============================================================ */

export const googleProvider = new GoogleAuthProvider();

googleProvider.setCustomParameters({
    prompt: "select_account"
});


/* ============================================================
   6. GENERAL CONSTANTS
============================================================ */

const RETURNING_USER_KEY = "businessos:returningUser";

const ATTRIBUTION_KEY = "businessos:signupAttribution";

const VERIFICATION_PAGE = "verify-email.html";

const LOGIN_PAGE = "login.html";

const SIGNUP_PAGE = "signup.html";

const WORKSPACE_PAGE = "menu.html";


/* ============================================================
   7. SAFE STORAGE HELPERS
============================================================ */

function readStorage(key) {

    try {

        return localStorage.getItem(key);

    } catch (error) {

        return null;

    }

}


function writeStorage(key, value) {

    try {

        localStorage.setItem(key, value);

        return true;

    } catch (error) {

        return false;

    }

}


function removeStorage(key) {

    try {

        localStorage.removeItem(key);

    } catch (error) {

        // Storage may be unavailable.
    }

}


/* ============================================================
   8. GENERAL VALIDATION
============================================================ */

function cleanText(value, maximumLength = 150) {

    if (typeof value !== "string") {

        return "";

    }

    return value.trim().slice(0, maximumLength);

}


function normalizeEmail(email) {

    return cleanText(email, 254).toLowerCase();

}


function validEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

}


function validPassword(password) {

    return (
        typeof password === "string" &&
        password.length >= 8
    );

}


function cleanCode(value) {

    if (typeof value !== "string") {

        return "";

    }

    const code = value.trim();

    if (!/^[a-zA-Z0-9_-]{1,80}$/.test(code)) {

        return "";

    }

    return code;

}


/* ============================================================
   9. USER-FRIENDLY ERROR HANDLING
============================================================ */

const AUTH_ERRORS = {

    "auth/email-already-in-use":
        "An account already exists with this email address.",

    "auth/invalid-email":
        "Please enter a valid email address.",

    "auth/weak-password":
        "Please choose a stronger password.",

    "auth/user-not-found":
        "No account was found with those details.",

    "auth/wrong-password":
        "The email address or password is incorrect.",

    "auth/invalid-credential":
        "The sign-in details are incorrect. Please try again.",

    "auth/too-many-requests":
        "Too many attempts. Please wait and try again.",

    "auth/network-request-failed":
        "A network connection is required. Please check your connection.",

    "auth/popup-blocked":
        "The Google sign-in window was blocked.",

    "auth/popup-closed-by-user":
        "Google sign-in was cancelled.",

    "auth/account-exists-with-different-credential":
        "An account already exists with another sign-in method.",

    "auth/requires-recent-login":
        "Please sign in again before making this change.",

    "auth/operation-not-allowed":
        "This sign-in method is not currently available.",

    "permission-denied":
        "You do not have permission to perform this action.",

    "unavailable":
        "The service is temporarily unavailable. Please try again."

};


export function getFriendlyError(error) {

    if (!error) {

        return "Something went wrong. Please try again.";

    }

    if (AUTH_ERRORS[error.code]) {

        return AUTH_ERRORS[error.code];

    }

    return (
        error.message ||
        "Something went wrong. Please try again."
    );

}


/* ============================================================
   10. REFERRAL AND INVITATION ATTRIBUTION
============================================================ */

/*
    Supported URL examples:

    signup.html?ref=REFERRAL_CODE

    signup.html?invite=INVITATION_CODE

    signup.html?business=BUSINESS_ID

    signup.html?ref=ABC123&invite=JOIN456
*/


export function captureAttributionFromURL() {

    try {

        const params = new URLSearchParams(
            window.location.search
        );

        const current = getPendingAttribution() || {};

        const referralCode = cleanCode(
            params.get("ref")
        );

        const invitationCode = cleanCode(
            params.get("invite")
        );

        const businessId = cleanCode(
            params.get("business")
        );

        const attribution = {

            referralCode:
                referralCode || current.referralCode || null,

            invitationCode:
                invitationCode || current.invitationCode || null,

            businessId:
                businessId || current.businessId || null,

            capturedAt: current.capturedAt || Date.now()

        };


        if (
            attribution.referralCode ||
            attribution.invitationCode ||
            attribution.businessId
        ) {

            writeStorage(
                ATTRIBUTION_KEY,
                JSON.stringify(attribution)
            );

        }

        return attribution;

    } catch (error) {

        return null;

    }

}


export function getPendingAttribution() {

    const stored = readStorage(ATTRIBUTION_KEY);

    if (!stored) {

        return null;

    }

    try {

        return JSON.parse(stored);

    } catch (error) {

        return null;

    }

}


export function clearPendingAttribution() {

    removeStorage(ATTRIBUTION_KEY);

}


captureAttributionFromURL();


/* ============================================================
   11. USER PROFILE CREATION
============================================================ */

/*
    Main account identity:

    users/{firebaseUID}

    A Firebase UID identifies one person.

    It is not a business ID, phone number or referral ID.
*/


export async function ensureUserProfile(
    user = auth.currentUser
) {

    if (!user) {

        throw new Error("Please sign in first.");

    }

    const userRef = doc(
        db,
        "users",
        user.uid
    );


    const providerIds = (user.providerData || []).map(
        provider => provider.providerId
    );


    const safeProfile = {

        uid: user.uid,

        email: user.email || null,

        displayName: user.displayName || "",

        photoURL: user.photoURL || null,

        emailVerified: Boolean(user.emailVerified),

        providerIds,

        updatedAt: serverTimestamp()

    };


    await runTransaction(db, async (transaction) => {

        const snapshot = await transaction.get(userRef);


        if (!snapshot.exists()) {

            transaction.set(userRef, {

                ...safeProfile,

                accountStatus: "active",

                onboardingStatus: "needs_profile",

                preferredLanguage: "en",

                country: null,

                createdAt: serverTimestamp()

            });

        } else {

            transaction.set(
                userRef,
                safeProfile,
                { merge: true }
            );

        }

    });


    return userRef;

}


/* ============================================================
   12. CREATE PROFILE AFTER REGISTRATION
============================================================ */

export async function createUserProfile(
    user,
    options = {}
) {

    if (!user) {

        throw new Error("A valid account is required.");

    }

    const userRef = doc(
        db,
        "users",
        user.uid
    );


    const attribution =
        options.attribution ||
        getPendingAttribution() ||
        {};


    const providerIds = (user.providerData || []).map(
        provider => provider.providerId
    );


    const profileData = {

        uid: user.uid,

        email: user.email || null,

        displayName: user.displayName || "",

        photoURL: user.photoURL || null,

        emailVerified: Boolean(user.emailVerified),

        providerIds,

        accountStatus: "active",

        onboardingStatus: "needs_profile",

        preferredLanguage: "en",

        country: null,

        signupAttribution: {

            referralCode:
                cleanCode(attribution.referralCode) || null,

            invitationCode:
                cleanCode(attribution.invitationCode) || null,

            businessId:
                cleanCode(attribution.businessId) || null

        },

        termsAccepted: options.acceptedTerms === true,

        createdAt: serverTimestamp(),

        updatedAt: serverTimestamp()

    };


    await runTransaction(db, async (transaction) => {

        const snapshot = await transaction.get(userRef);


        if (!snapshot.exists()) {

            transaction.set(userRef, profileData);

        } else {

            transaction.set(
                userRef,
                {
                    email: user.email || null,
                    displayName: user.displayName || "",
                    photoURL: user.photoURL || null,
                    emailVerified: Boolean(user.emailVerified),
                    providerIds,
                    updatedAt: serverTimestamp()
                },
                { merge: true }
            );

        }

    });


    return userRef;

}


/* ============================================================
   13. EMAIL VERIFICATION SETTINGS
============================================================ */

function getVerificationSettings() {

    return {

        url: new URL(
            LOGIN_PAGE + "?emailVerified=1",
            window.location.origin
        ).toString(),

        handleCodeInApp: false

    };

}


/* ============================================================
   14. EMAIL REGISTRATION
============================================================ */

export async function registerWithEmail({
    displayName,
    email,
    password,
    confirmPassword,
    acceptedTerms
} = {}) {

    await persistenceReady;


    const name = cleanText(displayName, 80);

    const normalizedEmail = normalizeEmail(email);


    if (!name) {

        throw new Error("Please enter your name.");

    }


    if (!validEmail(normalizedEmail)) {

        throw new Error("Please enter a valid email address.");

    }


    if (!validPassword(password)) {

        throw new Error(
            "Your password must contain at least 8 characters."
        );

    }


    if (
        confirmPassword !== undefined &&
        password !== confirmPassword
    ) {

        throw new Error("Your passwords do not match.");

    }


    if (acceptedTerms !== true) {

        throw new Error(
            "Please accept the Terms and Privacy Notice to continue."
        );

    }


    try {

        const credential =
            await createUserWithEmailAndPassword(
                auth,
                normalizedEmail,
                password
            );


        const user = credential.user;


        await firebaseUpdateProfile(user, {

            displayName: name

        });


        await createUserProfile(user, {

            acceptedTerms: true

        });


        writeStorage(
            RETURNING_USER_KEY,
            "true"
        );


        const verificationResult = {

            user,

            verificationSent: false,

            needsEmailVerification: true

        };


        try {

            await sendEmailVerification(
                user,
                getVerificationSettings()
            );

            verificationResult.verificationSent = true;

            clearPendingAttribution();

        } catch (verificationError) {

            verificationResult.verificationError =
                getFriendlyError(verificationError);

        }


        return verificationResult;

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   15. EMAIL/PASSWORD LOGIN
============================================================ */

export async function loginWithEmail({
    email,
    password
} = {}) {

    await persistenceReady;


    const normalizedEmail = normalizeEmail(email);


    if (!validEmail(normalizedEmail)) {

        throw new Error("Please enter a valid email address.");

    }


    if (!password) {

        throw new Error("Please enter your password.");

    }


    try {

        const credential =
            await signInWithEmailAndPassword(
                auth,
                normalizedEmail,
                password
            );


        await ensureUserProfile(credential.user);


        writeStorage(
            RETURNING_USER_KEY,
            "true"
        );


        return {

            user: credential.user,

            needsEmailVerification:
                !credential.user.emailVerified &&
                isEmailPasswordUser(credential.user)

        };

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   16. GOOGLE SIGN-IN
============================================================ */

/*
    Browser:

    1. Try Firebase popup.
    2. If a popup is blocked, try the configured native adapter.
    3. If native authentication is unavailable, use redirect.

    Android APK:

    A real native Google account chooser requires a configured
    Capacitor Firebase Authentication plugin. The optional
    adapter below is its integration point.

    The adapter must complete Firebase authentication and
    return a signed-in Firebase user credential.
*/


function isPopupFailure(error) {

    return [

        "auth/popup-blocked",

        "auth/operation-not-supported-in-this-environment",

        "auth/unsupported-persistence-type"

    ].includes(error?.code);

}


async function tryNativeGoogleSignIn() {

    const nativeSignIn =
        window.BusinessOSNativeGoogleSignIn;


    if (typeof nativeSignIn !== "function") {

        return null;

    }


    await nativeSignIn();


    const user = auth.currentUser;


    if (!user) {

        throw new Error(
            "Google authentication did not complete."
        );

    }


    await ensureUserProfile(user);


    writeStorage(
        RETURNING_USER_KEY,
        "true"
    );


    return {

        user,

        native: true,

        redirecting: false

    };

}


export async function loginWithGoogle() {

    await persistenceReady;


    try {

        const credential =
            await signInWithPopup(
                auth,
                googleProvider
            );


        await ensureUserProfile(credential.user);


        writeStorage(
            RETURNING_USER_KEY,
            "true"
        );


        return {

            user: credential.user,

            native: false,

            redirecting: false

        };

    } catch (error) {

        if (
            error?.code === "auth/popup-closed-by-user"
        ) {

            throw new Error(
                "Google sign-in was cancelled."
            );

        }


        if (!isPopupFailure(error)) {

            throw new Error(
                getFriendlyError(error)
            );

        }


        const isNative =
            Boolean(
                window.Capacitor?.isNativePlatform?.()
            );


        if (isNative) {

            try {

                const result =
                    await tryNativeGoogleSignIn();


                if (result) {

                    return result;

                }

            } catch (nativeError) {

                throw new Error(
                    getFriendlyError(nativeError)
                );

            }

        }


        try {

            await signInWithRedirect(
                auth,
                googleProvider
            );


            return {

                user: null,

                native: false,

                redirecting: true

            };

        } catch (redirectError) {

            throw new Error(
                getFriendlyError(redirectError)
            );

        }

    }

}


/* ============================================================
   17. COMPLETE GOOGLE REDIRECT RESULT
============================================================ */

export async function completeGoogleRedirect() {

    await persistenceReady;


    try {

        const result = await getRedirectResult(auth);


        if (!result || !result.user) {

            return null;

        }


        await ensureUserProfile(result.user);


        writeStorage(
            RETURNING_USER_KEY,
            "true"
        );


        return result.user;

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   18. FORGOT PASSWORD
============================================================ */

export async function sendPasswordRecoveryEmail(email) {

    await persistenceReady;


    const normalizedEmail = normalizeEmail(email);


    if (!validEmail(normalizedEmail)) {

        throw new Error("Please enter a valid email address.");

    }


    try {

        await sendPasswordResetEmail(
            auth,
            normalizedEmail,
            {

                url: new URL(
                    LOGIN_PAGE,
                    window.location.origin
                ).toString(),

                handleCodeInApp: false

            }
        );


        return {

            success: true,

            message:
                "If an account exists for this address, a password recovery link will be sent."

        };

    } catch (error) {

        /*
            Do not disclose whether an email has an account.
        */

        if ([

            "auth/user-not-found",

            "auth/invalid-email"

        ].includes(error.code)) {

            return {

                success: true,

                message:
                    "If an account exists for this address, a password recovery link will be sent."

            };

        }


        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   19. COMPLETE PASSWORD RESET
============================================================ */

export async function resetPassword({
    actionCode,
    newPassword,
    confirmPassword
} = {}) {

    if (!actionCode) {

        throw new Error(
            "The password recovery link is invalid or incomplete."
        );

    }


    if (!validPassword(newPassword)) {

        throw new Error(
            "Your new password must contain at least 8 characters."
        );

    }


    if (newPassword !== confirmPassword) {

        throw new Error(
            "Your passwords do not match."
        );

    }


    try {

        await confirmPasswordReset(
            auth,
            actionCode,
            newPassword
        );


        return {

            success: true,

            message: "Your password has been updated."

        };

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   20. RESEND EMAIL VERIFICATION
============================================================ */

export async function resendEmailVerification() {

    const user = auth.currentUser;


    if (!user) {

        throw new Error(
            "Please sign in to verify your email address."
        );

    }


    if (user.emailVerified) {

        return {

            success: true,

            message: "Your email address is already verified."

        };

    }


    try {

        await sendEmailVerification(
            user,
            getVerificationSettings()
        );


        return {

            success: true,

            message: "A new verification link has been sent."

        };

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   21. REFRESH EMAIL VERIFICATION STATUS
============================================================ */

export async function refreshEmailVerification() {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    await reload(user);


    if (user.emailVerified) {

        await ensureUserProfile(user);

    }


    return {

        verified: Boolean(user.emailVerified),

        user

    };

}


/* ============================================================
   22. CHECK ACCOUNT PROVIDER
============================================================ */

export function isEmailPasswordUser(user = auth.currentUser) {

    if (!user) {

        return false;

    }


    return (user.providerData || []).some(

        provider =>
            provider.providerId === "password"

    );

}


export function isGoogleUser(user = auth.currentUser) {

    if (!user) {

        return false;

    }


    return (user.providerData || []).some(

        provider =>
            provider.providerId === "google.com"

    );

}


/* ============================================================
   23. CURRENT USER INFORMATION
============================================================ */

export function getCurrentUser() {

    return auth.currentUser;

}


export function getCurrentUserId() {

    return auth.currentUser?.uid || null;

}


export function isAuthenticated() {

    return Boolean(auth.currentUser);

}


export async function getFirebaseIdToken(
    forceRefresh = false
) {

    const user = auth.currentUser;


    if (!user) {

        throw new Error(
            "Please sign in to continue."
        );

    }


    return getIdToken(
        user,
        forceRefresh
    );

}


/* ============================================================
   24. AUTHENTICATION STATE LISTENER
============================================================ */

export function observeAuthState(
    callback,
    errorCallback = () => {}
) {

    if (typeof callback !== "function") {

        throw new Error(
            "A valid authentication callback is required."
        );

    }


    return onAuthStateChanged(

        auth,

        async (user) => {

            if (user) {

                try {

                    await ensureUserProfile(user);

                } catch (error) {

                    console.error(
                        "Profile synchronization failed:",
                        error
                    );

                }

            }


            callback(user);

        },

        (error) => {

            errorCallback(
                getFriendlyError(error)
            );

        }

    );

}


/* ============================================================
   25. GET USER PROFILE
============================================================ */

export async function getUserProfile(uid = getCurrentUserId()) {

    if (!uid) {

        throw new Error("A user ID is required.");

    }


    const profileRef = doc(
        db,
        "users",
        uid
    );


    const snapshot = await getDoc(profileRef);


    if (!snapshot.exists()) {

        return null;

    }


    return {

        uid: snapshot.id,

        ...snapshot.data()

    };

}


/* ============================================================
   26. UPDATE PERSONAL USER PROFILE
============================================================ */

export async function updateUserProfile({
    displayName,
    photoURL,
    preferredLanguage,
    country,
    notificationPreferences
} = {}) {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    const firebaseUpdates = {};

    const databaseUpdates = {};


    if (displayName !== undefined) {

        const name = cleanText(displayName, 80);

        if (!name) {

            throw new Error(
                "Please enter a valid display name."
            );

        }

        firebaseUpdates.displayName = name;

        databaseUpdates.displayName = name;

    }


    if (photoURL !== undefined) {

        firebaseUpdates.photoURL = photoURL;

        databaseUpdates.photoURL = photoURL;

    }


    if (preferredLanguage !== undefined) {

        databaseUpdates.preferredLanguage =
            cleanText(preferredLanguage, 20);

    }


    if (country !== undefined) {

        databaseUpdates.country =
            cleanText(country, 80);

    }


    if (notificationPreferences !== undefined) {

        if (
            !notificationPreferences ||
            typeof notificationPreferences !== "object" ||
            Array.isArray(notificationPreferences)
        ) {

            throw new Error(
                "Invalid notification preferences."
            );

        }

        databaseUpdates.notificationPreferences =
            notificationPreferences;

    }


    if (Object.keys(firebaseUpdates).length > 0) {

        await firebaseUpdateProfile(
            user,
            firebaseUpdates
        );

    }


    if (Object.keys(databaseUpdates).length > 0) {

        await ensureUserProfile(user);


        databaseUpdates.updatedAt =
            serverTimestamp();


        await updateDoc(

            doc(db, "users", user.uid),

            databaseUpdates

        );

    }


    return getUserProfile(user.uid);

}


/* ============================================================
   27. CHANGE EMAIL ADDRESS
============================================================ */

export async function changeAccountEmail(newEmail) {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    const normalizedEmail = normalizeEmail(newEmail);


    if (!validEmail(normalizedEmail)) {

        throw new Error(
            "Please enter a valid email address."
        );

    }


    try {

        await updateEmail(
            user,
            normalizedEmail
        );


        await updateDoc(

            doc(db, "users", user.uid),

            {

                email: normalizedEmail,

                emailVerified: false,

                updatedAt: serverTimestamp()

            }

        );


        await sendEmailVerification(
            user,
            getVerificationSettings()
        );


        return {

            success: true,

            message:
                "Your new email address has been saved. Please verify it."

        };

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   28. CHANGE PASSWORD
============================================================ */

export async function changeAccountPassword({
    currentPassword,
    newPassword,
    confirmPassword
} = {}) {

    const user = auth.currentUser;


    if (!user || !user.email) {

        throw new Error(
            "This account cannot use email/password reauthentication."
        );

    }


    if (!validPassword(newPassword)) {

        throw new Error(
            "Your new password must contain at least 8 characters."
        );

    }


    if (newPassword !== confirmPassword) {

        throw new Error(
            "Your passwords do not match."
        );

    }


    try {

        const credential =
            EmailAuthProvider.credential(
                user.email,
                currentPassword
            );


        await reauthenticateWithCredential(
            user,
            credential
        );


        await updatePassword(
            user,
            newPassword
        );


        return {

            success: true,

            message: "Your password has been changed."

        };

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   29. SIGN OUT
============================================================ */

export async function logoutUser() {

    try {

        await signOut(auth);


        /*
            Keep the returning-user indicator.
            The splash page will direct this device to login.
        */

        writeStorage(
            RETURNING_USER_KEY,
            "true"
        );


        return {

            success: true

        };

    } catch (error) {

        throw new Error(
            getFriendlyError(error)
        );

    }

}


/* ============================================================
   30. AUTHENTICATION GUARD
============================================================ */

export async function requireAuthentication({
    redirectTo = LOGIN_PAGE
} = {}) {

    const user = auth.currentUser;


    if (!user) {

        const returnPath =
            window.location.pathname +
            window.location.search;


        const destination =
            new URL(
                redirectTo,
                window.location.href
            );


        destination.searchParams.set(
            "returnTo",
            returnPath
        );


        window.location.replace(
            destination.toString()
        );


        return null;

    }


    return user;

}


/* ============================================================
   31. BUSINESS NAME UTILITIES
============================================================ */

function normalizeBusinessName(name) {

    return cleanText(name, 120).toLowerCase();

}


function createBusinessSlug(name, id) {

    const base = cleanText(name, 100)

        .toLowerCase()

        .replace(/[^a-z0-9]+/g, "-")

        .replace(/^-+|-+$/g, "");


    return (
        (base || "business") +
        "-" +
        id.slice(0, 6).toLowerCase()
    );

}


/* ============================================================
   32. CREATE BUSINESS DRAFT
============================================================ */

/*
    One person can own multiple businesses.

    Business identity is separate from personal identity.

    businesses/{businessId}

    businesses/{businessId}/members/{uid}

    users/{uid}/businessMemberships/{businessId}
*/


export async function createBusinessDraft({

    name,

    category,

    description = "",

    country = "",

    region = "",

    city = ""

} = {}) {

    const user = auth.currentUser;


    if (!user) {

        throw new Error(
            "Please sign in before creating a business."
        );

    }


    const businessName = cleanText(name, 120);


    if (businessName.length < 2) {

        throw new Error(
            "Please enter a valid business name."
        );

    }


    const businessCategory = cleanText(
        category,
        80
    );


    if (!businessCategory) {

        throw new Error(
            "Please select a business category."
        );

    }


    await ensureUserProfile(user);


    const businessRef = doc(
        collection(db, "businesses")
    );


    const businessId = businessRef.id;


    const memberRef = doc(
        db,
        "businesses",
        businessId,
        "members",
        user.uid
    );


    const membershipIndexRef = doc(
        db,
        "users",
        user.uid,
        "businessMemberships",
        businessId
    );


    const userRef = doc(
        db,
        "users",
        user.uid
    );


    const businessData = {

        businessId,

        name: businessName,

        normalizedName:
            normalizeBusinessName(businessName),

        slug:
            createBusinessSlug(
                businessName,
                businessId
            ),

        category: businessCategory,

        description:
            cleanText(description, 1000),

        country: cleanText(country, 80),

        region: cleanText(region, 80),

        city: cleanText(city, 80),

        ownerUid: user.uid,

        status: "draft",

        verificationStatus: "unverified",

        createdAt: serverTimestamp(),

        updatedAt: serverTimestamp()

    };


    await runTransaction(db, async (transaction) => {

        const profileSnapshot =
            await transaction.get(userRef);


        if (!profileSnapshot.exists()) {

            throw new Error(
                "Your personal profile must be completed first."
            );

        }


        transaction.set(
            businessRef,
            businessData
        );


        transaction.set(memberRef, {

            uid: user.uid,

            businessId,

            role: "owner",

            status: "active",

            createdAt: serverTimestamp()

        });


        transaction.set(membershipIndexRef, {

            businessId,

            businessName,

            role: "owner",

            status: "active",

            createdAt: serverTimestamp()

        });


        transaction.update(userRef, {

            onboardingStatus: "business_created",

            updatedAt: serverTimestamp()

        });

    });


    return {

        businessId,

        business: businessData

    };

}


/* ============================================================
   33. GET BUSINESS MEMBERSHIP
============================================================ */

export async function getBusinessMembership(
    businessId,
    uid = getCurrentUserId()
) {

    if (!uid || !businessId) {

        throw new Error(
            "A user ID and business ID are required."
        );

    }


    const membershipRef = doc(

        db,

        "businesses",

        businessId,

        "members",

        uid

    );


    const snapshot = await getDoc(
        membershipRef
    );


    if (!snapshot.exists()) {

        return null;

    }


    return snapshot.data();

}


/* ============================================================
   34. CHECK BUSINESS ROLE
============================================================ */

export async function requireBusinessRole({

    businessId,

    allowedRoles = []

} = {}) {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    const membership =
        await getBusinessMembership(
            businessId,
            user.uid
        );


    if (
        !membership ||
        membership.status !== "active"
    ) {

        throw new Error(
            "You do not have access to this business."
        );

    }


    if (

        allowedRoles.length > 0 &&

        !allowedRoles.includes(
            membership.role
        )

    ) {

        throw new Error(
            "You do not have permission for this action."
        );

    }


    return membership;

}


/* ============================================================
   35. GET MY BUSINESSES
============================================================ */

export async function getMyBusinesses() {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    const memberships = await getDocs(

        collection(
            db,
            "users",
            user.uid,
            "businessMemberships"
        )

    );


    return memberships.docs.map(
        item => ({
            id: item.id,
            ...item.data()
        })
    );

}


/* ============================================================
   36. PHONE VERIFICATION STATUS
============================================================ */

/*
    Phone verification is required before the user starts
    a new one-to-one chat.

    IMPORTANT:

    OTP codes must be generated and verified by a trusted
    backend, never by this browser file.

    Private contact record:

    users/{uid}/private/contact

    The backend should control verifiedAt and phoneVerifiedAt.
*/


export async function isPhoneVerified() {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    const contactRef = doc(

        db,

        "users",

        user.uid,

        "private",

        "contact"

    );


    const snapshot = await getDoc(
        contactRef
    );


    if (!snapshot.exists()) {

        return false;

    }


    const data = snapshot.data();


    return Boolean(
        data.phoneVerifiedAt ||
        data.verifiedAt
    );

}


export async function requireVerifiedPhone() {

    const verified = await isPhoneVerified();


    if (!verified) {

        throw new Error(
            "Please verify your phone number before starting a new conversation."
        );

    }


    return true;

}


/* ============================================================
   37. SECURE PHONE VERIFICATION BACKEND INTEGRATION
============================================================ */

/*
    The backend adapter will be connected when the Node.js
    Cloud Functions or Cloud Run verification service exists.

    This file never generates a real OTP in browser JavaScript.
*/


export async function requestPhoneVerification(phoneNumber) {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    const normalizedPhone = cleanText(
        phoneNumber,
        25
    );


    if (!normalizedPhone) {

        throw new Error(
            "Please enter a valid phone number."
        );

    }


    const backend =
        window.BusinessOSBackend;


    if (
        !backend ||
        typeof backend.requestPhoneVerification !== "function"
    ) {

        throw new Error(
            "Phone verification is not yet available."
        );

    }


    const token = await getIdToken(user);


    return backend.requestPhoneVerification({

        phoneNumber: normalizedPhone,

        idToken: token

    });

}


export async function confirmPhoneVerification({

    phoneNumber,

    code

} = {}) {

    const user = auth.currentUser;


    if (!user) {

        throw new Error("Please sign in first.");

    }


    const backend =
        window.BusinessOSBackend;


    if (
        !backend ||
        typeof backend.confirmPhoneVerification !== "function"
    ) {

        throw new Error(
            "Phone verification is not yet available."
        );

    }


    const token = await getIdToken(user);


    return backend.confirmPhoneVerification({

        phoneNumber: cleanText(phoneNumber, 25),

        code: cleanText(code, 10),

        idToken: token

    });

}


/* ============================================================
   38. SPLASH SCREEN STATUS
============================================================ */

function updateSplashStatus(message, state = "loading") {

    const element =

        document.getElementById("auth-status") ||

        document.getElementById("authStatus") ||

        document.getElementById("loading-message");


    if (!element) {

        return;

    }


    element.textContent = message;

    element.dataset.state = state;

    element.setAttribute(
        "aria-live",
        "polite"
    );

}


/* ============================================================
   39. SPLASH SCREEN ROUTING
============================================================ */

/*
    INDEX.HTML ROUTING

    Signed-in verified account:
        menu.html

    Signed-in unverified email/password account:
        verify-email.html

    Returning signed-out user:
        login.html

    New visitor:
        signup.html
*/


let splashRoutingStarted = false;


export async function startSplashRouter() {

    if (splashRoutingStarted) {

        return;

    }


    splashRoutingStarted = true;


    updateSplashStatus(
        "Connecting securely...",
        "loading"
    );


    try {

        await persistenceReady;


        /*
            Consume any pending Google redirect result first.
        */

        try {

            await getRedirectResult(auth);

        } catch (redirectError) {

            console.warn(
                "No completed Google redirect was found.",
                redirectError
            );

        }


        const user = await new Promise(
            (resolve, reject) => {

                let unsubscribe = null;


                const stopListening = () => {

                    if (unsubscribe) {

                        unsubscribe();

                    }

                };


                unsubscribe = onAuthStateChanged(

                    auth,

                    (currentUser) => {

                        stopListening();

                        resolve(currentUser);

                    },

                    (error) => {

                        stopListening();

                        reject(error);

                    }

                );

            }
        );


        if (user) {

            updateSplashStatus(
                "Synchronizing your account...",
                "loading"
            );


            await ensureUserProfile(user);


            const needsVerification =

                isEmailPasswordUser(user) &&

                !user.emailVerified;


            if (needsVerification) {

                updateSplashStatus(
                    "Email verification required.",
                    "warning"
                );


                window.location.replace(
                    VERIFICATION_PAGE
                );


                return;

            }


            updateSplashStatus(
                "Account synchronized.",
                "success"
            );


            await new Promise(
                resolve => setTimeout(resolve, 350)
            );


            window.location.replace(
                WORKSPACE_PAGE
            );


            return;

        }


        const returningUser =
            readStorage(RETURNING_USER_KEY) === "true";


        if (returningUser) {

            updateSplashStatus(
                "No active session found.",
                "neutral"
            );


            window.location.replace(
                LOGIN_PAGE
            );


        } else {

            updateSplashStatus(
                "Welcome.",
                "neutral"
            );


            window.location.replace(
                SIGNUP_PAGE
            );

        }

    } catch (error) {

        console.error(
            "BusinessOS authentication error:",
            error
        );


        updateSplashStatus(
            "Unable to synchronize. Please try again.",
            "error"
        );

    }

}


/* ============================================================
   40. AUTOMATIC INDEX.HTML INITIALIZATION
============================================================ */

/*
    authentication.js automatically starts the splash
    authentication process when loaded from index.html.

    On other pages, it only exposes its authentication
    functions. It does not automatically redirect them.
*/


const currentPage =

    window.location.pathname

        .split("/")

        .pop()

        .toLowerCase();


if (
    currentPage === "" ||
    currentPage === "index.html"
) {

    void startSplashRouter();

}


/* ============================================================
   41. CENTRAL BUSINESSOS AUTHENTICATION OBJECT
============================================================ */

/*
    This object allows other JavaScript modules to access
    the central authentication service.

    Example:

    import {
        loginWithEmail,
        getCurrentUserId
    } from "./authentication.js";
*/


export const BusinessOSAuth = {

    auth,

    db,

    app,

    registerWithEmail,

    loginWithEmail,

    loginWithGoogle,

    completeGoogleRedirect,

    sendPasswordRecoveryEmail,

    resetPassword,

    resendEmailVerification,

    refreshEmailVerification,

    observeAuthState,

    getCurrentUser,

    getCurrentUserId,

    getFirebaseIdToken,

    isAuthenticated,

    isEmailPasswordUser,

    isGoogleUser,

    ensureUserProfile,

    createUserProfile,

    getUserProfile,

    updateUserProfile,

    changeAccountEmail,

    changeAccountPassword,

    logoutUser,

    requireAuthentication,

    createBusinessDraft,

    getBusinessMembership,

    requireBusinessRole,

    getMyBusinesses,

    captureAttributionFromURL,

    getPendingAttribution,

    clearPendingAttribution,

    isPhoneVerified,

    requireVerifiedPhone,

    requestPhoneVerification,

    confirmPhoneVerification,

    startSplashRouter,

    getFriendlyError

};


/* ============================================================
   BUSINESSOS AUTHENTICATION SERVICE — END
============================================================ */
