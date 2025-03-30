import { initializeApp } from "https://www.gstatic.com/firebasejs/11.5.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword } from "https://www.gstatic.com/firebasejs/11.5.0/firebase-auth.js";

const firebaseConfig = {
    apiKey: "AIzaSyDSKYsYwvM-0zof2rHtiKodp4z0HUTNiI4",
    authDomain: "sleepwell-7ec3a.firebaseapp.com",
    projectId: "sleepwell-7ec3a",
    storageBucket: "sleepwell-7ec3a.appspot.com",
    messagingSenderId: "37760004376",
    appId: "1:37760004376:web:87a663c13995e6f02c6e6d",
    measurementId: "G-E6ZWGCGF5S"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

async function login(event) {
    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        const idToken = await userCredential.user.getIdToken();

        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ idToken })
        });

        const result = await response.json();

        if (response.ok) {
            alert("Login successful!");
            window.location.href = "/dashboard";
        } else {
            alert(result.error || "Login failed.");
        }
    } catch (error) {
        alert("Login failed: " + error.message);
    }
}

document.getElementById("signinForm").addEventListener("submit", login);
