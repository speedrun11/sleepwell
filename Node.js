const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.applicationDefault(),
  databaseURL: 'https://sleepwell-7ec3a.firebaseio.com'
});

// Middleware to verify admin status
const verifyAdmin = async (req, res, next) => {
  try {
    const idToken = req.headers.authorization?.split('Bearer ')[1];
    if (!idToken) return res.status(401).send('Unauthorized');
    
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userDoc = await admin.firestore().collection('users').doc(decodedToken.uid).get();
    
    if (!userDoc.exists || !userDoc.data().isAdmin) {
      return res.status(403).send('Forbidden: Admin access required');
    }
    
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Admin verification error:', error);
    res.status(401).send('Unauthorized');
  }
};

// Delete user endpoint
app.delete('/api/users/:userId', verifyAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // First delete all sleep entries
    const entriesSnapshot = await admin.firestore().collection('sleepEntries')
      .where('userId', '==', userId)
      .get();
    
    const batch = admin.firestore().batch();
    entriesSnapshot.forEach(doc => {
      batch.delete(doc.ref);
    });
    
    // Then delete the user document
    batch.delete(admin.firestore().collection('users').doc(userId));
    await batch.commit();
    
    // Finally delete the auth user
    await admin.auth().deleteUser(userId);
    
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('User deletion error:', error);
    res.status(500).json({ 
      error: error.message,
      code: error.code || 'unknown-error'
    });
  }
});

// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});