import * as admin from "firebase-admin";
const serviceAccount = "growthmagnet-e9985-firebase-adminsdk-fbsvc-f689db1603.json"
import { logger } from "./logger";

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

export async function verifyIdToken(idToken: string) {
    if (!idToken) {
        throw new Error("ID token is required");
    }

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        return decodedToken;
    } catch (error) {
        logger.error("googleAuthError: Error verifying ID token:", error);
        throw new Error("googleAuthError: Invalid ID token");
    }
}

export async function getUserDetails(uid: string) {
    try {
        const userRecord = await admin.auth().getUser(uid);
        return userRecord;
    } catch (error) {
        logger.error("googleAuthError: Error fetching user details:", error);
        throw new Error("googleAuthError: Failed to retrieve user details");
    }
}
