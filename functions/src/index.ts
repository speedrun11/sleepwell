import * as functions from "firebase-functions";
import * as admin from "firebase-admin";

admin.initializeApp();

interface RequestData {
  uid: string;
}

/**
 * Type guard for request data validation.
 * @param {unknown} data - The data to validate
 * @returns {boolean} True if data matches RequestData interface
 */
function isRequestData(data: unknown): data is RequestData {
  return typeof data === "object" &&
        data !== null &&
        "uid" in data &&
        typeof (data as {uid: unknown}).uid === "string";
}

// Explicitly type the callable function parameters
exports.setAdminClaim = functions.https.onCall<RequestData>(async (request) => {
  // Validate request data
  if (!isRequestData(request.data)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Request must contain a valid uid string"
    );
  }

  // Verify authentication context exists
  if (!request.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "Authentication required"
    );
  }

  // Verify admin privileges
  if (!request.auth.token.admin) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admins can assign admin privileges"
    );
  }

  try {
    // Set custom admin claim
    await admin.auth().setCustomUserClaims(request.data.uid, {admin: true});

    // Update Firestore document
    await admin.firestore().collection("users").doc(request.data.uid).update({
      isAdmin: true,
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      success: true,
      message: `User ${request.data.uid} is now an admin.`,
    };
  } catch (error) {
    functions.logger.error("Error setting admin claim:", error);
    throw new functions.https.HttpsError(
      "internal",
      "Failed to set admin claim",
      error instanceof Error ? error.message : String(error),
    );
  }
});