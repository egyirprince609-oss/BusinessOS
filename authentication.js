/*
 * BUSINESSOS - CENTRAL AUTHENTICATION AND IDENTITY SERVICE
 * Firebase Project: business-os-by
 * Firebase SDK: 13.2.0
 *
 * Responsibilities:
 * - Firebase initialization and persistence
 * - Email/password registration and login
 * - Google authentication
 * - Email verification and verification-link handling
 * - Password recovery and password changes
 * - Firebase UID identity and special display ID
 * - User profile creation and synchronization
 * - Profile photo URL management
 * - Referral and invitation attribution
 * - Business registration and membership
 * - Business role checks
 * - Phone verification integration point
 * - Authentication guards and splash routing
 *
 * SECURITY:
 * - Firebase UID is the permanent account identity.
 * - Business IDs are separate from personal user IDs.
 * - Privileged operations require trusted backend validation.
 * - Never place SMTP passwords, service-account keys,
 *   SMS credentials or social API secrets in this file.
 */


// ============================================================
// 1. FIREBASE SDK IMPORTS
// ============================================================

import {
    initializeApp,
    getApps
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
    sendEmailVerification as firebaseSendEmailVerification,
    sendPasswordResetEmail,
    confirmPasswordReset,
    checkActionCode,
    applyActionCode,
    updateProfile as firebaseUpdateProfile,
    updateEmail as firebaseUpdateEmail,
    updatePassword as firebaseUpdatePassword,
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


// ============================================================
// 2. FIREBASE PROJECT CONFIGURATION
// ============================================================

const firebaseConfig = Object.freeze({

    apiKey: "AIzaSyCaItsHbMSCA-jKJ5IldpRD0NEW_M9eJ68",

    authDomain: "business-os-by.firebaseapp.com",

    projectId: "business-os-by",

    storageBucket: "business-os-by.firebasestorage.app",

    messagingSenderId: "970110196253",

    appId: "1:970110196253:web:c7f9f4472f6e084c5544f4",

    measurementId: "G-KBGYD6D73L"

});


// ============================================================
// 3. BUSINESSOS ROUTES
// ============================================================

export const BUSINESSOS_ROUTES = Object.freeze({

    index: "index.html",

    signup: "signup.html",

    login: "login.html",

    verification: "verify-email.html",

    passwordRecovery: "forgot.html",

    workspace: "menu.html",

    profileSetup: "profile-setup.html",

    businessSetup: "business-setup.html"

});


// ============================================================
// 4. BUSINESSOS COLLECTION REGISTRY
// ============================================================

/*
 * These names establish the central collection registry.
 *
 * Actual product records belong in their respective
 * Firestore collections, not inside the personal auth profile.
 */

export const BUSINESSOS_COLLECTIONS = Object.freeze({

    users: "users",

    businesses: "businesses",

    businessSearch: "businessSearch",

    publicProfiles: "publicProfiles",

    chatRequests: "chatRequests",

    conversations: "conversations",

    campaigns: "campaigns",

    mediaAssets: "mediaAssets",

    socialConnections: "socialConnections",

    publishJobs: "publishJobs",

    notifications: "notifications",

    auditLogs: "auditLogs",

    groups: "groups",

    products: "products",

    services: "services",

    orders: "orders",

    payments: "payments",

    inventoryItems: "inventoryItems",

    suppliers: "suppliers",

    purchaseOrders: "purchaseOrders",

    branches: "branches",

    employees: "employees",

    attendanceEvents: "attendanceEvents",

    leaveRequests: "leaveRequests",

    tasks: "tasks",

    projects: "projects",

    productionOrders: "productionOrders",

    machines: "machines",

    qualityInspections: "qualityInspections",

    aiRequests: "aiRequests",

    subscriptions: "subscriptions",

    reports: "reports",

    reportsQueue: "reportsQueue",

    moderationQueue: "moderationQueue"

});


// ============================================================
// 5. GENERAL CONSTANTS
// ============================================================

const STORAGE_KEYS = Object.freeze({

    returningUser: "businessos:returningUser",

    signupAttribution: "businessos:signupAttribution",

    verificationLastSent: "businessos:verificationLastSent"

});


const FIREBASE_SDK_VERSION = "13.2.0";

const VERIFICATION_RESEND_SECONDS = 60;


// ============================================================
// 6. INITIALIZE FIREBASE
// ============================================================

export const app = getApps().length
    ? getApps()[0]
    : initializeApp(firebaseConfig);


export const auth = getAuth(app);


export const db = getFirestore(app);


export const googleProvider = new GoogleAuthProvider();


googleProvider.setCustomParameters({

    prompt: "select_account"

});


auth.languageCode = "en";


// ============================================================
// 7. AUTHENTICATION PERSISTENCE
// ============================================================

export const persistenceReady = setPersistence(

    auth,

    browserLocalPersistence

).catch((error) => {

    console.warn(
        "BusinessOS could not enable local authentication persistence:",
        error
    );

    return null;

});


export const firebaseReady = persistenceReady.then(() => ({

    app,

    auth,

    db

}));


async function requireFirebase() {

    await firebaseReady;

    if (!auth || !db) {

        throw new Error(
            "BusinessOS account services are not available."
        );

    }

}


// ============================================================
// 8. SAFE STORAGE HELPERS
// ============================================================

function readStorage(key) {

    try {

        return window.localStorage.getItem(key);

    } catch {

        return null;

    }

}


function writeStorage(key, value) {

    try {

        window.localStorage.setItem(
            key,
            String(value)
        );

        return true;

    } catch {

        return false;

    }

}


function removeStorage(key) {

    try {

        window.localStorage.removeItem(key);

    } catch {

        // Storage may be unavailable.

    }

}


function markReturningUser() {

    writeStorage(
        STORAGE_KEYS.returningUser,
        "true"
    );

}


// ============================================================
// 9. GENERAL VALIDATION
// ============================================================

function cleanText(value, maxLength = 150) {

    return typeof value === "string"

        ? value.trim().replace(/\s+/g, " ").slice(0, maxLength)

        : "";

}


export function normalizeEmail(value) {

    return cleanText(value, 254).toLowerCase();

}


export function isValidEmail(value) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(
        normalizeEmail(value)
    );

}


// ============================================================
// 10. PASSWORD POLICY
// ============================================================

export function getPasswordChecks(password) {

    const value =
        typeof password === "string" ? password : "";

    return Object.freeze({

        length:
            value.length >= 6 &&
            value.length <= 400,

        uppercase:
            /[A-Z]/.test(value),

        lowercase:
            /[a-z]/.test(value),

        special:
            /[^A-Za-z0-9\s]/.test(value)

    });

}


export function validatePassword(password) {

    const checks = getPasswordChecks(password);


    if (!checks.length) {

        throw new Error(
            "Your password must contain between 6 and 400 characters."
        );

    }


    if (!checks.uppercase) {

        throw new Error(
            "Your password must contain at least one uppercase letter."
        );

    }


    if (!checks.lowercase) {

        throw new Error(
            "Your password must contain at least one lowercase letter."
        );

    }


    if (!checks.special) {

        throw new Error(
            "Your password must contain at least one special character."
        );

    }


    return true;

}


// ============================================================
// 11. SAFE REFERRAL CODE VALIDATION
// ============================================================

function cleanCode(value, maxLength = 80) {

    const code = cleanText(value, maxLength);

    return /^[A-Za-z0-9_-]{1,80}$/.test(code)
        ? code
        : "";

}


// ============================================================
// 12. CENTRAL ERROR HANDLING
// ============================================================

export function getFriendlyError(error) {

    const code = String(error?.code || "");

    const messages = {

        "auth/email-already-in-use":
            "An account already exists with this email address. Sign in instead.",

        "auth/invalid-email":
            "Please enter a valid email address.",

        "auth/weak-password":
            "Please choose a stronger password.",

        "auth/user-not-found":
            "The email address or password is incorrect.",

        "auth/wrong-password":
            "The email address or password is incorrect.",

        "auth/invalid-credential":
            "The email address or password is incorrect.",

        "auth/too-many-requests":
            "Too many attempts. Please wait before trying again.",

        "auth/network-request-failed":
            "A network connection is required. Check your connection and try again.",

        "auth/popup-blocked":
            "The Google sign-in window was blocked.",

        "auth/popup-closed-by-user":
            "Google sign-in was cancelled.",

        "auth/cancelled-popup-request":
            "A Google sign-in request is already running.",

        "auth/account-exists-with-different-credential":
            "An account already exists with another sign-in method.",

        "auth/unauthorized-domain":
            "This website domain is not authorised in Firebase Authentication settings.",

        "auth/operation-not-allowed":
            "This sign-in method is not enabled in Firebase Authentication.",

        "auth/expired-action-code":
            "This verification link has expired. Request a new verification email.",

        "auth/invalid-action-code":
            "This verification link is invalid or has already been used.",

        "auth/requires-recent-login":
            "Please sign in again before making this security-sensitive change.",

        "permission-denied":
            "Firestore denied this operation. Check your deployed Firestore Rules and profile schema.",

        "unavailable":
            "The service is temporarily unavailable. Please try again."

    };


    const friendly = new Error(

        messages[code] ||

        error?.message ||

        "Something went wrong. Please try again."

    );


    friendly.code =
        code || "businessos/unknown-error";


    friendly.cause = error;


    return friendly;

}


// ============================================================
// 13. REFERRAL AND INVITATION ATTRIBUTION
// ============================================================

export function captureAttributionFromURL() {

    if (typeof window === "undefined") {

        return null;

    }


    const params = new URLSearchParams(
        window.location.search
    );


    const previous = getPendingAttribution() || {};


    const attribution = {

        referralCode:
            cleanCode(params.get("ref")) ||
            previous.referralCode ||
            null,

        invitationCode:
            cleanCode(params.get("invite")) ||
            previous.invitationCode ||
            null,

        businessId:
            cleanCode(params.get("business")) ||
            previous.businessId ||
            null

    };


    if (

        attribution.referralCode ||

        attribution.invitationCode ||

        attribution.businessId

    ) {

        writeStorage(

            STORAGE_KEYS.signupAttribution,

            JSON.stringify(attribution)

        );

    }


    return attribution;

}


export function getPendingAttribution() {

    const stored = readStorage(
        STORAGE_KEYS.signupAttribution
    );


    if (!stored) {

        return null;

    }


    try {

        const item = JSON.parse(stored);


        return {

            referralCode:
                cleanCode(item?.referralCode) || null,

            invitationCode:
                cleanCode(item?.invitationCode) || null,

            businessId:
                cleanCode(item?.businessId) || null

        };

    } catch {

        removeStorage(
            STORAGE_KEYS.signupAttribution
        );

        return null;

    }

}


export function clearPendingAttribution() {

    removeStorage(
        STORAGE_KEYS.signupAttribution
    );

}


// ============================================================
// 14. USER IDENTITY
// ============================================================

export function getCurrentUser() {

    return auth.currentUser || null;

}


export function getCurrentUserId() {

    return auth.currentUser?.uid || null;

}


/*
 * Firebase UID remains the permanent identity.
 *
 * The special ID below is a stable display reference derived
 * from that UID. It is not a separate authentication credential.
 */

export function getBusinessOSSpecialId(
    uid = getCurrentUserId()
) {

    if (!uid) {

        return null;

    }

    return `BOS-${uid}`;

}


export function getCurrentUserIdentity() {

    const user = auth.currentUser;


    if (!user) {

        return null;

    }


    return Object.freeze({

        uid: user.uid,

        userId: user.uid,

        specialId: getBusinessOSSpecialId(user.uid),

        email: user.email || null,

        displayName: user.displayName || null,

        photoURL: user.photoURL || null,

        emailVerified: Boolean(user.emailVerified),

        providerIds: (user.providerData || []).map(
            item => item.providerId
        )

    });

}


// ============================================================
// NATIVE ANDROID / iOS APP DETECTION
// ============================================================

export function isNativeBusinessOSApp() {

    try {

        return Boolean(

            typeof window !== "undefined" &&

            window.Capacitor &&

            typeof window.Capacitor.isNativePlatform === "function" &&

            window.Capacitor.isNativePlatform()

        );

    } catch (error) {

        console.warn(
            "BusinessOS native platform detection failed:",
            error
        );

        return false;

    }

}


// ============================================================
// 15. FIRESTORE USER PROFILE REFERENCES
// ============================================================

export function getUserProfileReference(
    uid = getCurrentUserId()
) {

    if (!uid) {

        throw new Error(
            "A Firebase user ID is required."
        );

    }


    return doc(
        db,
        "users",
        uid
    );

}


function makeSafeAttribution() {

    const attribution =
        getPendingAttribution() || {};


    return {

        referralCode:
            cleanCode(attribution.referralCode) || null,

        invitationCode:
            cleanCode(attribution.invitationCode) || null,

        businessId:
            cleanCode(attribution.businessId) || null

    };

}


// ============================================================
// 16. CREATE AND SYNCHRONIZE USER PROFILE
// ============================================================

/*
 * Profile path:
 *
 * users/{firebaseUID}
 *
 * Stores:
 * - Firebase UID
 * - Email
 * - Display name
 * - Profile photo URL
 * - Email verification status
 * - Authentication provider IDs
 * - Account status
 * - Onboarding status
 * - Preferred language
 * - Country
 * - Terms acceptance
 * - Referral/invitation attribution
 * - Creation and update timestamps
 *
 * Private phone verification is stored separately at:
 *
 * users/{uid}/private/contact
 *
 * The trusted backend controls phone verification status.
 */

export async function ensureUserProfile(
    user = getCurrentUser(),
    options = {}
) {

    await requireFirebase();


    if (!user?.uid) {

        throw new Error(
            "A signed-in account is required."
        );

    }


    /*
     * Refresh the Firebase user before building the profile payload.
     * This keeps emailVerified and the ID-token claims in sync with
     * the values checked by the deployed Firestore Rules.
     */

    await reload(user);

    await getIdToken(user, true);


    const profileRef = getUserProfileReference(
        user.uid
    );


    const providerIds = [

        ...new Set(

            (user.providerData || [])

                .map(item => cleanText(item?.providerId, 80))

                .filter(Boolean)

        )

    ].slice(0, 5);


    // Firebase's email claim is compared exactly by the Firestore Rules.
    // Do not lowercase or otherwise transform this value before saving it.

    const email = typeof user.email === "string"
        ? user.email
        : null;


    const emailVerified = Boolean(user.emailVerified);


    const optionDisplayName = cleanText(
        options.displayName,
        80
    );


    const authDisplayName = cleanText(
        user.displayName,
        80
    );


    const authPhotoURL =
        typeof user.photoURL === "string" &&
        /^https:\/\//i.test(user.photoURL) &&
        user.photoURL.length <= 2048
            ? user.photoURL
            : null;


    const attribution = makeSafeAttribution();


    /*
     * Use a transaction so two simultaneous sign-in/profile-sync
     * operations cannot both decide that the same profile is missing.
     */

    await runTransaction(

        db,

        async (transaction) => {

            const snapshot = await transaction.get(
                profileRef
            );


            const existingData = snapshot.exists()
                ? snapshot.data()
                : {};


            const savedDisplayName =
                typeof existingData.displayName === "string" &&
                existingData.displayName.length <= 80
                    ? existingData.displayName
                    : "";


            const displayName =
                optionDisplayName ||
                authDisplayName ||
                savedDisplayName ||
                "";


            // Preserve a profile photo already saved in Firestore when
            // Firebase Authentication does not provide a current photo.

            const savedPhotoURL =
                typeof existingData.photoURL === "string" &&
                existingData.photoURL.length <= 2048
                    ? existingData.photoURL
                    : null;


            const photoURL = authPhotoURL || savedPhotoURL || null;


            if (!snapshot.exists()) {

                const data = {

                    uid: user.uid,

                    email,

                    displayName,

                    photoURL,

                    emailVerified,

                    providerIds,

                    accountStatus: "active",

                    onboardingStatus: "needs_profile",

                    preferredLanguage: "en",

                    country: null,

                    ...(options.acceptedTerms === true
                        ? { termsAccepted: true }
                        : {}),

                    signupAttribution: attribution,

                    createdAt: serverTimestamp(),

                    updatedAt: serverTimestamp()

                };


                transaction.set(
                    profileRef,
                    data
                );


                return;

            }


            /*
             * UID is an immutable identity field in the deployed rules.
             * A legacy document with a different/missing UID cannot safely
             * be repaired by a normal client update, so report it clearly.
             */

            if (existingData.uid !== user.uid) {

                throw new Error(
                    "Your existing BusinessOS profile has an invalid UID. Contact support to repair this profile securely."
                );

            }


            const updates = {

                email,

                displayName,

                photoURL,

                emailVerified,

                providerIds,

                updatedAt: serverTimestamp()

            };


            // Firestore Rules allow termsAccepted to be added/changed only
            // to true. Never write false or treat Google sign-in as consent.

            if (
                options.acceptedTerms === true &&
                existingData.termsAccepted !== true
            ) {

                updates.termsAccepted = true;

            }


            transaction.update(
                profileRef,
                updates
            );

        }

    );


    // Read back the saved document so callers receive the committed values,
    // not unresolved serverTimestamp() sentinels from the write payload.

    const savedSnapshot = await getDoc(
        profileRef
    );


    if (!savedSnapshot.exists()) {

        throw new Error(
            "BusinessOS could not confirm that your user profile was saved. Please try signing in again."
        );

    }


    return {

        uid: user.uid,

        ...savedSnapshot.data()

    };

}


export async function createUserProfile(
    user,
    options = {}
) {

    return ensureUserProfile(
        user,
        options
    );

}


// ============================================================
// 17. READ USER PROFILE
// ============================================================

export async function getUserProfile(
    uid = getCurrentUserId()
) {

    await requireFirebase();


    if (!uid) {

        throw new Error(
            "A Firebase user ID is required."
        );

    }


    const snapshot = await getDoc(
        getUserProfileReference(uid)
    );


    return snapshot.exists()

        ? {
            uid: snapshot.id,
            ...snapshot.data()
          }

        : null;

}


// ============================================================
// 18. UPDATE PERSONAL USER PROFILE
// ============================================================

export async function updateUserProfile({

    displayName,

    photoURL,

    preferredLanguage,

    country,

    notificationPreferences

} = {}) {

    await requireFirebase();


    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Please sign in first."
        );

    }


    // Ensure the profile exists and is synchronized before applying
    // profile edits. updateDoc() cannot create a missing document.

    await ensureUserProfile(user);


    const authUpdates = {};

    const profileUpdates = {};


    if (displayName !== undefined) {

        const name = cleanText(
            displayName,
            80
        );


        if (name.length < 2) {

            throw new Error(
                "Your display name must contain at least 2 characters."
            );

        }


        authUpdates.displayName = name;

        profileUpdates.displayName = name;

    }


    if (photoURL !== undefined) {

        const imageUrl = cleanText(
            photoURL,
            2048
        );


        if (
            imageUrl &&
            !/^https:\/\//i.test(imageUrl)
        ) {

            throw new Error(
                "Profile image URLs must use HTTPS."
            );

        }


        authUpdates.photoURL = imageUrl || null;

        profileUpdates.photoURL = imageUrl || null;

    }


    if (preferredLanguage !== undefined) {

        profileUpdates.preferredLanguage =
            cleanText(preferredLanguage, 20);

    }


    if (country !== undefined) {

        profileUpdates.country =
            cleanText(country, 80);

    }


    if (notificationPreferences !== undefined) {

        if (

            !notificationPreferences ||

            typeof notificationPreferences !== "object" ||

            Array.isArray(notificationPreferences)

        ) {

            throw new Error(
                "Notification preferences must be an object."
            );

        }


        const allowed = [

            "email",

            "push",

            "securityAlerts",

            "productUpdates",

            "marketing"

        ];


        if (

            Object.keys(notificationPreferences).some(

                key => !allowed.includes(key)

            )

        ) {

            throw new Error(
                "An unsupported notification preference was supplied."
            );

        }


        profileUpdates.notificationPreferences =
            notificationPreferences;

    }


    if (Object.keys(authUpdates).length) {

        await firebaseUpdateProfile(
            user,
            authUpdates
        );

    }


    if (Object.keys(profileUpdates).length) {

        profileUpdates.updatedAt =
            serverTimestamp();


        await updateDoc(

            getUserProfileReference(user.uid),

            profileUpdates

        );

    }


    return getUserProfile(user.uid);

}


// ============================================================
// 19. CHANGE ACCOUNT EMAIL
// ============================================================

export async function changeAccountEmail(newEmail) {

    await requireFirebase();


    const user = getCurrentUser();

    const email = normalizeEmail(newEmail);


    if (!user) {

        throw new Error(
            "Sign in before changing your email address."
        );

    }


    if (!isValidEmail(email)) {

        throw new Error(
            "Enter a valid new email address."
        );

    }


    try {

        await firebaseUpdateEmail(
            user,
            email
        );


        await reload(user);

        await getIdToken(user, true);


        await firebaseSendEmailVerification(
            user,
            getEmailActionSettings()
        );


        try {

            await ensureUserProfile(user);

        } catch (profileError) {

            console.warn(
                "New email saved; profile sync will retry:",
                profileError
            );

        }


        return {

            success: true,

            verificationSent: true,

            message:
                "Your email address was changed. Verify the new address to continue."

        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 20. CHANGE ACCOUNT PASSWORD
// ============================================================

export async function changeAccountPassword({

    currentPassword,

    newPassword,

    confirmPassword

} = {}) {

    await requireFirebase();


    const user = getCurrentUser();


    if (!user?.email) {

        throw new Error(
            "A signed-in email/password account is required."
        );

    }


    if (!currentPassword) {

        throw new Error(
            "Enter your current password."
        );

    }


    validatePassword(newPassword);


    if (newPassword !== confirmPassword) {

        throw new Error(
            "Your new passwords do not match."
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


        await firebaseUpdatePassword(
            user,
            newPassword
        );


        return {
            success: true
        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 21. EMAIL VERIFICATION ACTION SETTINGS
// ============================================================

function getEmailActionSettings() {

    const origin = window.location.origin;


    return {

        /*
         * This is the continue URL after Firebase completes
         * the email action handler.
         *
         * The custom action handler itself must be configured
         * separately in Firebase Authentication email templates.
         */

        url: new URL(

            BUSINESSOS_ROUTES.workspace,

            origin

        ).toString(),

        handleCodeInApp: false

    };

}


// ============================================================
// 22. SEND REAL FIREBASE VERIFICATION EMAIL
// ============================================================

export async function sendEmailVerification(
    user = getCurrentUser()
) {

    await requireFirebase();


    if (!user) {

        throw new Error(
            "Sign in to the account that needs email verification."
        );

    }


    await reload(user);


    if (user.emailVerified) {

        return {

            sent: false,

            alreadyVerified: true,

            cooldown: false

        };

    }


    const lastSentAt = Number(

        readStorage(
            STORAGE_KEYS.verificationLastSent
        ) || 0

    );


    const secondsRemaining =

        VERIFICATION_RESEND_SECONDS -

        Math.floor(
            (Date.now() - lastSentAt) / 1000
        );


    if (
        lastSentAt > 0 &&
        secondsRemaining > 0
    ) {

        return {

            sent: false,

            alreadyVerified: false,

            cooldown: true,

            secondsRemaining

        };

    }


    try {

        /*
         * This calls Firebase Authentication's real
         * sendEmailVerification function.
         *
         * Firebase creates the one-time action link and
         * sends its configured verification email.
         */

        await firebaseSendEmailVerification(

            user,

            getEmailActionSettings()

        );


        writeStorage(

            STORAGE_KEYS.verificationLastSent,

            String(Date.now())

        );


        return {

            sent: true,

            alreadyVerified: false,

            cooldown: false

        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 23. RESEND VERIFICATION EMAIL
// ============================================================

export async function resendEmailVerification() {

    return sendEmailVerification(
        getCurrentUser()
    );

}


// ============================================================
// 24. REFRESH EMAIL VERIFICATION STATUS
// ============================================================

export async function refreshEmailVerification() {

    await requireFirebase();


    const user = getCurrentUser();


    if (!user) {

        return {

            signedIn: false,

            emailVerified: false,

            user: null

        };

    }


    await reload(user);

    await getIdToken(user, true);


    let profileSyncError = null;


    try {

        await ensureUserProfile(user);

    } catch (error) {

        profileSyncError = getFriendlyError(error);

        console.warn(
            "Email is verified in Firebase Auth, but profile sync is pending:",
            error
        );

    }


    return {

        signedIn: true,

        emailVerified: Boolean(user.emailVerified),

        user,

        profileSyncError

    };

}


// ============================================================
// 25. COMPLETE EMAIL VERIFICATION LINK
// ============================================================

/*
 * Firebase custom action handler parameters:
 *
 * mode=verifyEmail
 * oobCode=ONE_TIME_CODE
 * apiKey=FIREBASE_API_KEY
 * continueUrl=OPTIONAL_CONTINUE_URL
 * lang=OPTIONAL_LANGUAGE
 *
 * This function validates and applies the one-time code.
 */

export async function completeEmailVerificationFromLink(
    url = window.location.href
) {

    await requireFirebase();


    const parsed = new URL(url);

    const mode =
        parsed.searchParams.get("mode");

    const actionCode =
        parsed.searchParams.get("oobCode");


    if (
        mode !== "verifyEmail" ||
        !actionCode
    ) {

        return {

            handled: false,

            verified: false,

            reason: "missing-action-code"

        };

    }


    try {

        const actionInfo = await checkActionCode(
            auth,
            actionCode
        );


        const verifiedEmail = normalizeEmail(
            actionInfo?.data?.email || ""
        );


        if (!verifiedEmail) {

            throw new Error(
                "Firebase did not return the email associated with this verification link."
            );

        }


        await applyActionCode(
            auth,
            actionCode
        );


        // Remove the one-time code from the URL.

        parsed.searchParams.delete("oobCode");

        parsed.searchParams.delete("apiKey");

        parsed.searchParams.delete("mode");

        parsed.searchParams.delete("lang");

        parsed.searchParams.delete("continueUrl");


        const remaining =
            parsed.searchParams.toString();


        window.history.replaceState(

            {},

            document.title,

            `${parsed.pathname}${remaining ? `?${remaining}` : ""}${parsed.hash}`

        );


        const currentUser = getCurrentUser();


        const matchesCurrentSession = Boolean(

            currentUser?.email &&

            normalizeEmail(currentUser.email) === verifiedEmail

        );


        if (matchesCurrentSession) {

            await reload(currentUser);

            await getIdToken(currentUser, true);


            try {

                await ensureUserProfile(currentUser);

            } catch (profileError) {

                console.warn(
                    "Verification succeeded; profile sync will retry later:",
                    profileError
                );

            }

        }


        return {

            handled: true,

            verified: true,

            email: verifiedEmail,

            matchesCurrentSession,

            user: matchesCurrentSession
                ? currentUser
                : null

        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 26. EMAIL/PASSWORD REGISTRATION
// ============================================================

export async function registerWithEmail({

    displayName,

    email,

    password,

    confirmPassword,

    acceptedTerms

} = {}) {

    await requireFirebase();


    const name = cleanText(
        displayName,
        80
    );


    const normalizedEmail =
        normalizeEmail(email);


    if (name.length < 2) {

        throw new Error(
            "Enter your full name (at least 2 characters)."
        );

    }


    if (!isValidEmail(normalizedEmail)) {

        throw new Error(
            "Enter a valid email address."
        );

    }


    validatePassword(password);


    if (
        confirmPassword !== undefined &&
        password !== confirmPassword
    ) {

        throw new Error(
            "Your passwords do not match."
        );

    }


    if (acceptedTerms !== true) {

        throw new Error(
            "Accept the Terms of Service and Privacy Notice to continue."
        );

    }


    // Create the actual Firebase Authentication account.

    let credential;


    try {

        credential =
            await createUserWithEmailAndPassword(

                auth,

                normalizedEmail,

                password

            );

    } catch (error) {

        throw getFriendlyError(error);

    }


    const user = credential.user;


    markReturningUser();


    /*
     * A profile-sync failure must not prevent us from attempting
     * to send the verification email after account creation.
     */

    let profileSyncError = null;


    try {

        await firebaseUpdateProfile(

            user,

            { displayName: name }

        );


        await reload(user);


        await ensureUserProfile(

            user,

            {

                displayName: name,

                acceptedTerms: true

            }

        );

    } catch (error) {

        profileSyncError = getFriendlyError(error);

        console.error(
            "Account created; profile synchronisation needs attention:",
            error
        );

    }


    // Send the real Firebase verification email.

    let verificationSent = false;

    let verificationError = null;


    try {

        const result = await sendEmailVerification(user);


        verificationSent = Boolean(

            result.sent ||

            result.alreadyVerified

        );


        if (result.cooldown) {

            verificationError = new Error(

                `Please wait ${result.secondsRemaining} seconds before requesting another email.`

            );

        }

    } catch (error) {

        verificationError = getFriendlyError(error);

    }


    return {

        user,

        profileSyncError,

        verificationSent,

        emailVerificationSent: verificationSent,

        verificationError,

        emailVerificationError: verificationError,

        needsEmailVerification: !user.emailVerified,

        requiresEmailVerification: !user.emailVerified

    };

}


// ============================================================
// 27. EMAIL/PASSWORD LOGIN
// ============================================================

export async function loginWithEmail({

    email,

    password

} = {}) {

    await requireFirebase();


    const normalizedEmail =
        normalizeEmail(email);


    if (!isValidEmail(normalizedEmail)) {

        throw new Error(
            "Enter a valid email address."
        );

    }


    if (
        typeof password !== "string" ||
        !password
    ) {

        throw new Error(
            "Enter your password."
        );

    }


    try {

        const credential =
            await signInWithEmailAndPassword(

                auth,

                normalizedEmail,

                password

            );


        await reload(credential.user);

        await getIdToken(credential.user, true);


        markReturningUser();


        let profileSyncError = null;


        try {

            await ensureUserProfile(
                credential.user
            );

        } catch (error) {

            profileSyncError = getFriendlyError(error);

        }


        return {

            user: credential.user,

            emailVerified: Boolean(
                credential.user.emailVerified
            ),

            needsEmailVerification:
                !credential.user.emailVerified,

            profileSyncError

        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 28. GOOGLE SIGN-IN
// ============================================================

function isPopupFallbackError(error) {

    return [

        "auth/popup-blocked",

        "auth/operation-not-supported-in-this-environment",

        "auth/web-storage-unsupported",

        "auth/unsupported-persistence-type"

    ].includes(String(error?.code || ""));

}


export async function loginWithGoogle() {

    await requireFirebase();


    try {

        const credential =
            await signInWithPopup(

                auth,

                googleProvider

            );


        await reload(credential.user);


        // Google sign-in is not, by itself, acceptance of the Terms.
        await ensureUserProfile(credential.user);


        markReturningUser();


        return {

            user: credential.user,

            redirecting: false

        };

    } catch (error) {

        if (

            error?.code === "auth/popup-closed-by-user" ||

            error?.code === "auth/cancelled-popup-request"

        ) {

            throw getFriendlyError(error);

        }


        if (!isPopupFallbackError(error)) {

            throw getFriendlyError(error);

        }


        // Fallback when popup authentication is not supported.

        try {

            await signInWithRedirect(
                auth,
                googleProvider
            );


            return {

                user: null,

                redirecting: true

            };

        } catch (redirectError) {

            throw getFriendlyError(redirectError);

        }

    }

}


// ============================================================
// 29. COMPLETE GOOGLE REDIRECT
// ============================================================

export async function completeGoogleRedirect() {

    await requireFirebase();


    try {

        const result = await getRedirectResult(auth);


        if (!result?.user) {

            return null;

        }


        // Google sign-in is not, by itself, acceptance of the Terms.
        await ensureUserProfile(result.user);


        markReturningUser();


        return {

            user: result.user

        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 30. PASSWORD RECOVERY
// ============================================================

export async function sendPasswordRecoveryEmail(email) {

    await requireFirebase();


    const normalizedEmail =
        normalizeEmail(email);


    if (!isValidEmail(normalizedEmail)) {

        throw new Error(
            "Enter a valid email address."
        );

    }


    try {

        await sendPasswordResetEmail(

            auth,

            normalizedEmail,

            {

                url: new URL(

                    BUSINESSOS_ROUTES.login,

                    window.location.origin

                ).toString(),

                handleCodeInApp: false

            }

        );

    } catch (error) {

        // Do not reveal whether an email is registered.

        if (

            ![

                "auth/user-not-found",

                "auth/invalid-email"

            ].includes(error?.code)

        ) {

            throw getFriendlyError(error);

        }

    }


    return {

        success: true,

        message:
            "If an account matches that address, a password-reset email will be sent."

    };

}


// ============================================================
// 31. COMPLETE PASSWORD RESET
// ============================================================

export async function resetPassword({

    actionCode,

    newPassword,

    confirmPassword

} = {}) {

    await requireFirebase();


    if (!actionCode) {

        throw new Error(
            "The password-reset link is incomplete."
        );

    }


    validatePassword(newPassword);


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
            success: true
        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 32. PROVIDER CHECKS
// ============================================================

export function isEmailPasswordUser(
    user = getCurrentUser()
) {

    return Boolean(

        user?.providerData?.some(

            provider =>
                provider.providerId === "password"

        )

    );

}


export function isGoogleUser(
    user = getCurrentUser()
) {

    return Boolean(

        user?.providerData?.some(

            provider =>
                provider.providerId === "google.com"

        )

    );

}


export function isAuthenticated() {

    return Boolean(
        getCurrentUser()
    );

}


// ============================================================
// 33. FIREBASE ID TOKEN
// ============================================================

export async function getFirebaseIdToken(
    forceRefresh = false
) {

    await requireFirebase();


    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Sign in before requesting an account token."
        );

    }


    return getIdToken(

        user,

        Boolean(forceRefresh)

    );

}


// ============================================================
// 34. AUTHENTICATION STATE LISTENER
// ============================================================

export function observeAuthState(
    callback,

    errorCallback = console.error

) {

    if (typeof callback !== "function") {

        throw new TypeError(
            "An authentication callback is required."
        );

    }


    return onAuthStateChanged(

        auth,

        callback,

        errorCallback

    );

}


export async function waitForInitialAuthState() {

    await firebaseReady;


    return new Promise((resolve, reject) => {

        let unsubscribe = null;


        unsubscribe = onAuthStateChanged(

            auth,

            (user) => {

                if (unsubscribe) {

                    unsubscribe();

                }


                resolve(user || null);

            },

            (error) => {

                if (unsubscribe) {

                    unsubscribe();

                }


                reject(error);

            }

        );

    });

}


// ============================================================
// 35. AUTHENTICATION GUARD
// ============================================================

export async function requireAuthentication({

    redirectTo = BUSINESSOS_ROUTES.login

} = {}) {

    await firebaseReady;


    const user =
        await waitForInitialAuthState();


    if (!user) {

        const destination = new URL(

            redirectTo,

            window.location.href

        );


        destination.searchParams.set(

            "returnTo",

            window.location.pathname +
            window.location.search

        );


        window.location.replace(
            destination.toString()
        );


        return null;

    }


    return user;

}


// ============================================================
// 36. VERIFIED EMAIL GUARD
// ============================================================

export async function requireVerifiedUser({

    redirectTo = BUSINESSOS_ROUTES.verification

} = {}) {

    const user =
        await requireAuthentication();


    if (!user) {

        return null;

    }


    await reload(user);


    if (

        isEmailPasswordUser(user) &&

        !user.emailVerified

    ) {

        window.location.replace(
            redirectTo
        );


        return null;

    }


    return user;

}


// ============================================================
// 37. SIGN OUT
// ============================================================

export async function logoutUser() {

    await requireFirebase();


    try {

        await signOut(auth);


        markReturningUser();


        return {
            success: true
        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 38. BUSINESS NAME UTILITIES
// ============================================================

function normalizeBusinessName(name) {

    return cleanText(
        name,
        120
    ).toLowerCase();

}


function createBusinessSlug(name, id) {

    const base = cleanText(
        name,
        100
    )

        .toLowerCase()

        .replace(/[^a-z0-9]+/g, "-")

        .replace(/^-+|-+$/g, "");


    return `${base || "business"}-${id.slice(0, 6).toLowerCase()}`;

}


// ============================================================
// 39. CREATE BUSINESS DRAFT
// ============================================================

/*
 * Business path:
 *
 * businesses/{businessId}
 *
 * Membership:
 *
 * businesses/{businessId}/members/{uid}
 *
 * User membership index:
 *
 * users/{uid}/businessMemberships/{businessId}
 *
 * A user may own multiple businesses.
 */

export async function createBusinessDraft({

    name,

    category,

    description = "",

    country = "",

    region = "",

    city = ""

} = {}) {

    await requireFirebase();


    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Sign in before creating a business."
        );

    }


    if (

        isEmailPasswordUser(user) &&

        !user.emailVerified

    ) {

        throw new Error(
            "Verify your email before creating a business."
        );

    }


    const businessName = cleanText(
        name,
        120
    );


    const businessCategory = cleanText(
        category,
        80
    );


    if (businessName.length < 2) {

        throw new Error(
            "Enter a valid business name."
        );

    }


    if (!businessCategory) {

        throw new Error(
            "Select a business category."
        );

    }


    const userRef = getUserProfileReference(
        user.uid
    );


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

        country:
            cleanText(country, 80),

        region:
            cleanText(region, 80),

        city:
            cleanText(city, 80),

        ownerUid: user.uid,

        status: "draft",

        verificationStatus: "unverified",

        createdAt: serverTimestamp(),

        updatedAt: serverTimestamp()

    };


    try {

        await runTransaction(

            db,

            async (transaction) => {

                const profileSnapshot =
                    await transaction.get(userRef);


                if (!profileSnapshot.exists()) {

                    throw new Error(
                        "Create your personal profile before registering a business."
                    );

                }


                transaction.set(
                    businessRef,
                    businessData
                );


                transaction.set(

                    memberRef,

                    {

                        uid: user.uid,

                        businessId,

                        role: "owner",

                        status: "active",

                        createdAt: serverTimestamp()

                    }

                );


                transaction.set(

                    membershipIndexRef,

                    {

                        businessId,

                        businessName,

                        role: "owner",

                        status: "active",

                        createdAt: serverTimestamp()

                    }

                );


                transaction.update(

                    userRef,

                    {

                        onboardingStatus: "business_created",

                        updatedAt: serverTimestamp()

                    }

                );

            }

        );


        return {

            businessId,

            business: businessData

        };

    } catch (error) {

        throw getFriendlyError(error);

    }

}


// ============================================================
// 40. GET BUSINESS MEMBERSHIP
// ============================================================

export async function getBusinessMembership(

    businessId,

    uid = getCurrentUserId()

) {

    await requireFirebase();


    if (!uid || !businessId) {

        throw new Error(
            "A user ID and business ID are required."
        );

    }


    const snapshot = await getDoc(

        doc(

            db,

            "businesses",

            businessId,

            "members",

            uid

        )

    );


    return snapshot.exists()
        ? snapshot.data()
        : null;

}


// ============================================================
// 41. BUSINESS ROLE VALIDATION
// ============================================================

export async function requireBusinessRole({

    businessId,

    allowedRoles = []

} = {}) {

    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Sign in first."
        );

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

        allowedRoles.length &&

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


// ============================================================
// 42. GET MY BUSINESSES
// ============================================================

export async function getMyBusinesses() {

    await requireFirebase();


    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Sign in first."
        );

    }


    const snapshot = await getDocs(

        collection(

            db,

            "users",

            user.uid,

            "businessMemberships"

        )

    );


    return snapshot.docs.map(

        item => ({

            id: item.id,

            ...item.data()

        })

    );

}


// ============================================================
// 43. PHONE VERIFICATION STATUS
// ============================================================

/*
 * Private path:
 *
 * users/{uid}/private/contact
 *
 * The trusted backend writes phoneVerifiedAt.
 *
 * Do not let a browser set its own verified flag.
 */

export async function isPhoneVerified() {

    await requireFirebase();


    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Sign in first."
        );

    }


    const snapshot = await getDoc(

        doc(

            db,

            "users",

            user.uid,

            "private",

            "contact"

        )

    );


    if (!snapshot.exists()) {

        return false;

    }


    const value =
        snapshot.data().phoneVerifiedAt;


    return Boolean(

        value instanceof Date ||

        value?.toDate

    );

}


// ============================================================
// 44. PHONE VERIFICATION BACKEND ADAPTER
// ============================================================

async function callPhoneVerificationBackend(
    action,
    payload
) {

    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Sign in first."
        );

    }


    const service = window.BusinessOSBackend;


    const method =

        action === "request"

            ? service?.requestPhoneVerification

            : service?.confirmPhoneVerification;


    if (typeof method !== "function") {

        throw new Error(
            "The secure phone-verification backend has not been deployed yet."
        );

    }


    const idToken = await getIdToken(
        user,
        true
    );


    return method({

        ...payload,

        idToken

    });

}


// ============================================================
// 45. REQUEST PHONE VERIFICATION
// ============================================================

export async function requestPhoneVerification(phoneNumber) {

    const phone = cleanText(
        phoneNumber,
        25
    );


    if (!/^\+[1-9]\d{7,14}$/.test(phone)) {

        throw new Error(
            "Enter a phone number in international format, for example +233XXXXXXXXX."
        );

    }


    return callPhoneVerificationBackend(

        "request",

        { phoneNumber: phone }

    );

}


// ============================================================
// 46. CONFIRM PHONE VERIFICATION
// ============================================================

export async function confirmPhoneVerification({

    phoneNumber,

    code

} = {}) {

    const phone = cleanText(
        phoneNumber,
        25
    );


    const otp = cleanText(
        code,
        10
    );


    if (!/^\+[1-9]\d{7,14}$/.test(phone)) {

        throw new Error(
            "Enter a valid international phone number."
        );

    }


    if (!/^\d{6}$/.test(otp)) {

        throw new Error(
            "Enter the six-digit verification code."
        );

    }


    return callPhoneVerificationBackend(

        "confirm",

        {

            phoneNumber: phone,

            code: otp

        }

    );

}


// ============================================================
// 47. REQUIRE VERIFIED PHONE
// ============================================================

export async function requireVerifiedPhone() {

    const verified =
        await isPhoneVerified();


    if (!verified) {

        throw new Error(
            "Verify your phone number before starting a new conversation."
        );

    }


    return true;

}


// ============================================================
// 48. PRIVATE CONTACT REFERENCE
// ============================================================

export function getPrivateContactReference(
    uid = getCurrentUserId()
) {

    if (!uid) {

        throw new Error(
            "A Firebase user ID is required."
        );

    }


    return doc(

        db,

        "users",

        uid,

        "private",

        "contact"

    );

}


// ============================================================
// 49. BUSINESS MEMBERSHIP REFERENCE
// ============================================================

export function getBusinessMembershipReference(

    businessId,

    uid = getCurrentUserId()

) {

    if (!businessId || !uid) {

        throw new Error(
            "A business ID and user ID are required."
        );

    }


    return doc(

        db,

        "businesses",

        businessId,

        "members",

        uid

    );

}


// ============================================================
// 50. ACCOUNT DELETION REQUEST
// ============================================================

export async function requestAccountDeletion() {

    const user = getCurrentUser();


    if (!user) {

        throw new Error(
            "Sign in before requesting account deletion."
        );

    }


    const service = window.BusinessOSBackend;


    if (
        typeof service?.requestAccountDeletion !== "function"
    ) {

        throw new Error(
            "Secure account deletion has not been configured on the backend yet."
        );

    }


    const idToken = await getIdToken(
        user,
        true
    );


    return service.requestAccountDeletion({

        idToken

    });

}


// ============================================================
// 51. SPLASH SCREEN AUTHENTICATION ROUTING
// ============================================================

export async function startSplashRouter() {

    const page = window.location.pathname

        .split("/")

        .pop()

        .toLowerCase();


    if (
        page &&
        page !== BUSINESSOS_ROUTES.index
    ) {

        return;

    }


    try {

        await firebaseReady;


        // Consume any completed Google redirect.

        await completeGoogleRedirect();


        const user =
            await waitForInitialAuthState();


        if (user) {

            await reload(user);


            if (

                isEmailPasswordUser(user) &&

                !user.emailVerified

            ) {

                window.location.replace(
                    BUSINESSOS_ROUTES.verification
                );


                return;

            }


            try {

                await ensureUserProfile(user);

            } catch (error) {

                console.warn(
                    "Profile sync will retry after sign-in:",
                    error
                );

            }


            window.location.replace(
                BUSINESSOS_ROUTES.workspace
            );


            return;

        }


        const returning =

            readStorage(
                STORAGE_KEYS.returningUser
            ) === "true";


        window.location.replace(

            returning

                ? BUSINESSOS_ROUTES.login

                : BUSINESSOS_ROUTES.signup

        );

    } catch (error) {

        console.error(
            "BusinessOS startup authentication failed:",
            error
        );


        const status =

            document.getElementById("auth-status") ||

            document.getElementById("authStatus");


        if (status) {

            status.textContent =
                "BusinessOS could not connect. Check your internet connection and try again.";

        }

    }

}


// ============================================================
// 52. AUTOMATIC INDEX.HTML INITIALIZATION
// ============================================================

if (
    typeof window !== "undefined" &&
    typeof document !== "undefined"
) {

    const page = window.location.pathname

        .split("/")

        .pop()

        .toLowerCase();


    if (
        !page ||
        page === BUSINESSOS_ROUTES.index
    ) {

        if (document.readyState === "loading") {

            document.addEventListener(

                "DOMContentLoaded",

                () => void startSplashRouter(),

                { once: true }

            );

        } else {

            void startSplashRouter();

        }

    }

}


// ============================================================
// 53. BACKWARDS-COMPATIBLE EXPORT ALIASES
// ============================================================

/*
 * These aliases retain compatibility with pages that use
 * the older BusinessOS authentication function names.
 */

export const createAccountWithEmail =
    registerWithEmail;


export const signInWithEmail =
    loginWithEmail;


export const signInWithGoogle =
    loginWithGoogle;


export const refreshEmailVerificationState =
    refreshEmailVerification;


export const signOutBusinessOS =
    logoutUser;


export const captureSignupContext =
    captureAttributionFromURL;


export const getSignupContext =
    getPendingAttribution;


export const clearSignupContext =
    clearPendingAttribution;


export const requireSignedInUser =
    requireAuthentication;


export const BUSINESSOS_AUTH_VERSION =
    FIREBASE_SDK_VERSION;


// ============================================================
// 54. CENTRAL BUSINESSOS AUTHENTICATION OBJECT
// ============================================================

export const BusinessOSAuth = Object.freeze({

    app,

    auth,

    db,

    registerWithEmail,

    loginWithEmail,

    loginWithGoogle,

    completeGoogleRedirect,

    sendEmailVerification,

    resendEmailVerification,

    refreshEmailVerification,

    completeEmailVerificationFromLink,

    sendPasswordRecoveryEmail,

    resetPassword,

    ensureUserProfile,

    createUserProfile,

    getUserProfile,

    updateUserProfile,

    getCurrentUser,

    getCurrentUserId,

    getCurrentUserIdentity,

    getBusinessOSSpecialId,

    getFirebaseIdToken,

    isAuthenticated,

    isNativeBusinessOSApp,

    isEmailPasswordUser,

    isGoogleUser,

    observeAuthState,

    waitForInitialAuthState,

    requireAuthentication,

    requireVerifiedUser,

    logoutUser,

    changeAccountEmail,

    changeAccountPassword,

    createBusinessDraft,

    getBusinessMembership,

    requireBusinessRole,

    getMyBusinesses,

    isPhoneVerified,

    requireVerifiedPhone,

    requestPhoneVerification,

    confirmPhoneVerification,

    requestAccountDeletion,

    getFriendlyError

});


// ============================================================
// BUSINESSOS CENTRAL AUTHENTICATION SERVICE - END
// ============================================================
