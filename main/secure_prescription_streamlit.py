# Secure Medical Prescription Transmission System - Streamlit Frontend
# Requirements: pip install streamlit pycryptodome

import os
import json
import base64
import datetime
import hashlib
import tempfile
import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class User:
    def __init__(self, name, role):
        """Initialize a user with a name and role (doctor or pharmacy)"""
        self.name = name
        self.role = role  # 'doctor' or 'pharmacy'
        self.key_pair = None
        self.public_key_str = None
        
    def generate_key_pair(self):
        """Generate RSA key pair for the user"""
        self.key_pair = RSA.generate(2048)
        self.public_key_str = self.key_pair.publickey().export_key().decode('utf-8')
        
    def get_public_key(self):
        """Return public key as a string"""
        return self.public_key_str
    
    def get_private_key(self):
        """Return private key object (should be kept secure)"""
        return self.key_pair

class Prescription:
    def __init__(self, doctor_name, patient_name, patient_id, medication, dosage, frequency, duration):
        """Initialize a prescription with relevant medical information"""
        self.doctor_name = doctor_name
        self.patient_name = patient_name
        self.patient_id = patient_id
        self.medication = medication
        self.dosage = dosage
        self.frequency = frequency
        self.duration = duration
        self.date_issued = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.prescription_id = self._generate_prescription_id()
        
    def _generate_prescription_id(self):
        """Generate a unique prescription ID"""
        unique_data = f"{self.doctor_name}{self.patient_name}{self.patient_id}{self.date_issued}"
        return hashlib.sha256(unique_data.encode()).hexdigest()[:16]
        
    def to_dict(self):
        """Convert prescription to a dictionary"""
        return {
            "prescription_id": self.prescription_id,
            "doctor_name": self.doctor_name,
            "patient_name": self.patient_name,
            "patient_id": self.patient_id,
            "medication": self.medication,
            "dosage": self.dosage,
            "frequency": self.frequency,
            "duration": self.duration,
            "date_issued": self.date_issued
        }
        
    def to_json(self):
        """Convert prescription to a JSON string"""
        return json.dumps(self.to_dict())

class DoctorPortal:
    def __init__(self, doctor):
        """Initialize doctor portal with the doctor user"""
        self.doctor = doctor
        if not self.doctor.key_pair:
            self.doctor.generate_key_pair()
        
    def create_prescription(self, patient_name, patient_id, medication, dosage, frequency, duration):
        """Create a new prescription"""
        return Prescription(
            self.doctor.name,
            patient_name,
            patient_id,
            medication,
            dosage,
            frequency,
            duration
        )
    
    def encrypt_and_sign_prescription(self, prescription, pharmacy_public_key_str):
        """Encrypt prescription with AES, encrypt AES key with pharmacy's public key,
        and sign the prescription data with the doctor's private key"""
        
        # Convert prescription to JSON
        prescription_json = prescription.to_json()
        
        # Generate random AES key and encrypt prescription
        aes_key = get_random_bytes(16)  # 128-bit AES key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        encrypted_data = cipher_aes.encrypt(pad(prescription_json.encode('utf-8'), AES.block_size))
        
        # Sign the original prescription data with doctor's private key
        h = SHA256.new(prescription_json.encode('utf-8'))
        signature = pkcs1_15.new(self.doctor.key_pair).sign(h)
        
        # Encrypt the AES key with pharmacy's public key
        pharmacy_public_key = RSA.import_key(pharmacy_public_key_str)
        cipher_rsa = PKCS1_OAEP.new(pharmacy_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        # Prepare the package
        secure_package = {
            "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(cipher_aes.iv).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "doctor_public_key": self.doctor.get_public_key(),
            "pharmacy_name": self.doctor.name,
            "target_pharmacy": prescription.patient_id  # Store which pharmacy this is for
        }
        
        return secure_package
    
    def save_secure_package(self, secure_package, filename="prescription_package.json"):
        """Save the secure package to a file"""
        with open(filename, 'w') as f:
            json.dump(secure_package, f, indent=4)
        return filename

class PharmacyPortal:
    def __init__(self, pharmacy):
        """Initialize pharmacy portal with the pharmacy user"""
        self.pharmacy = pharmacy
        if not self.pharmacy.key_pair:
            self.pharmacy.generate_key_pair()
        self.prescriptions = {}  # Store verified prescriptions
    
    def decrypt_and_verify_prescription(self, secure_package):
        """Decrypt and verify the prescription package"""
        try:
            # Extract components
            encrypted_data = base64.b64decode(secure_package["encrypted_data"])
            encrypted_aes_key = base64.b64decode(secure_package["encrypted_aes_key"])
            iv = base64.b64decode(secure_package["iv"])
            signature = base64.b64decode(secure_package["signature"])
            doctor_public_key_str = secure_package["doctor_public_key"]
            
            # Decrypt the AES key using pharmacy's private key
            cipher_rsa = PKCS1_OAEP.new(self.pharmacy.key_pair)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            
            # Decrypt the prescription data using the AES key
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
            prescription_json = decrypted_data.decode('utf-8')
            
            # Verify the signature using doctor's public key
            doctor_public_key = RSA.import_key(doctor_public_key_str)
            h = SHA256.new(prescription_json.encode('utf-8'))
            
            try:
                pkcs1_15.new(doctor_public_key).verify(h, signature)
                # Convert JSON back to dictionary
                prescription_dict = json.loads(prescription_json)
                
                # Store verified prescription
                self.prescriptions[prescription_dict["prescription_id"]] = prescription_dict
                
                return True, prescription_dict
                
            except (ValueError, TypeError) as e:
                return False, f"Signature verification failed! Prescription might be tampered. Error: {str(e)}"
                
        except Exception as e:
            return False, f"Error processing prescription: {str(e)}"
    
    def load_secure_package(self, file_content):
        """Load a secure package from file content"""
        try:
            secure_package = json.loads(file_content)
            return secure_package
        except Exception as e:
            return None

# Initialize session state with pharmacy keys that persist between sessions
def initialize_pharmacy_keys():
    if 'pharmacy_keys' not in st.session_state:
        st.session_state.pharmacy_keys = {}
    
    # Initialize standard pharmacies if not already done
    if len(st.session_state.pharmacy_keys) == 0:
        pharmacies = ["Central Pharmacy", "City Drugs", "Health Pharmacy"]
        for pharmacy_name in pharmacies:
            if pharmacy_name not in st.session_state.pharmacy_keys:
                user = User(pharmacy_name, "pharmacy")
                user.generate_key_pair()
                st.session_state.pharmacy_keys[pharmacy_name] = user

# Streamlit app
def main():
    st.set_page_config(
        page_title="Secure Medical Prescription System",
        page_icon="🏥",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🔐 Secure Medical Prescription System")
    
    # Initialize pharmacy keys that will persist
    initialize_pharmacy_keys()
    
    # Initialize session state
    if 'doctor_user' not in st.session_state:
        st.session_state.doctor_user = None
    if 'doctor_portal' not in st.session_state:
        st.session_state.doctor_portal = None
    if 'pharmacy_portal' not in st.session_state:
        st.session_state.pharmacy_portal = None
    if 'prescription_file' not in st.session_state:
        st.session_state.prescription_file = None
    if 'secure_package' not in st.session_state:
        st.session_state.secure_package = None
    if 'decrypted_prescription' not in st.session_state:
        st.session_state.decrypted_prescription = None
    if 'tampered_file' not in st.session_state:
        st.session_state.tampered_file = None
    if 'current_pharmacy' not in st.session_state:
        st.session_state.current_pharmacy = None
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.selectbox(
        "Choose a mode",
        ["Home", "Doctor Portal", "Pharmacy Portal", "Run Demo", "Tamper Detection"]
    )
    
    # Home page
    if app_mode == "Home":
        show_home()
    
    # Doctor Portal
    elif app_mode == "Doctor Portal":
        show_doctor_portal()
    
    # Pharmacy Portal
    elif app_mode == "Pharmacy Portal":
        show_pharmacy_portal()
    
    # Run Demo
    elif app_mode == "Run Demo":
        run_demo()
    
    # Tamper Detection
    elif app_mode == "Tamper Detection":
        show_tamper_detection()
    
def show_home():
    st.header("Welcome to the Secure Medical Prescription System")
    
    st.write("""
    This system enables secure creation, transmission, and verification of medical prescriptions using modern cryptography techniques.
    
    ### Features:
    - 🔒 End-to-end encryption of prescription data
    - 🔏 Digital signatures to verify prescription authenticity
    - 🛡️ Tamper detection to prevent unauthorized modifications
    - 🔑 Public key infrastructure for secure key exchange
    
    ### How to use:
    1. Use the **Doctor Portal** to create and encrypt prescriptions
    2. Use the **Pharmacy Portal** to decrypt and verify prescriptions
    3. Try the **Run Demo** to see a complete workflow
    4. Test the **Tamper Detection** to see how security features work
    
    Navigate using the sidebar to explore different features.
    """)
    
    st.info("This is a demonstration application for educational purposes only.")

def show_doctor_portal():
    st.header("👨‍⚕️ Doctor Portal")
    
    # Doctor credentials
    with st.expander("Doctor Credentials", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            doctor_name = st.text_input("Doctor Name", value="Dr. Smith")
        
        with col2:
            if st.button("Generate Key Pair"):
                st.session_state.doctor_user = User(doctor_name, "doctor")
                st.session_state.doctor_user.generate_key_pair()
                st.session_state.doctor_portal = DoctorPortal(st.session_state.doctor_user)
                st.success(f"Key pair generated for {doctor_name}")
    
    # Cannot proceed without doctor key pair
    if not st.session_state.doctor_user:
        st.warning("Please generate a key pair to continue")
        return
    
    # Prescription creation
    st.subheader("Create Prescription")
    
    col1, col2 = st.columns(2)
    
    with col1:
        patient_name = st.text_input("Patient Name", value="John Doe")
        patient_id = st.text_input("Patient ID", value="P12345")
        medication = st.text_input("Medication", value="Amoxicillin")
    
    with col2:
        dosage = st.text_input("Dosage", value="500mg")
        frequency = st.text_input("Frequency", value="3 times daily")
        duration = st.text_input("Duration", value="7 days")
    
    # Pharmacy selection
    st.subheader("Select Pharmacy")
    
    # Get all available pharmacies from the session state
    available_pharmacies = list(st.session_state.pharmacy_keys.keys())
    
    selected_pharmacy = st.selectbox(
        "Select a pharmacy",
        available_pharmacies
    )
    
    # Create and encrypt prescription
    if st.button("Create and Encrypt Prescription"):
        with st.spinner("Creating and encrypting prescription..."):
            # Create prescription
            prescription = st.session_state.doctor_portal.create_prescription(
                patient_name=patient_name,
                patient_id=patient_id,
                medication=medication,
                dosage=dosage,
                frequency=frequency,
                duration=duration
            )
            
            # Get selected pharmacy
            selected_pharmacy_user = st.session_state.pharmacy_keys[selected_pharmacy]
            
            # Encrypt and sign
            secure_package = st.session_state.doctor_portal.encrypt_and_sign_prescription(
                prescription,
                selected_pharmacy_user.get_public_key()
            )
            
            # Add pharmacy name to secure package
            secure_package["target_pharmacy"] = selected_pharmacy
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as f:
                json.dump(secure_package, f, indent=4)
                st.session_state.prescription_file = f.name
            
            st.session_state.secure_package = secure_package
            
            st.success("Prescription created and encrypted successfully!")
    
    # Download prescription
    if st.session_state.prescription_file:
        with open(st.session_state.prescription_file, 'r') as f:
            prescription_content = f.read()
        
        st.download_button(
            label="Download Encrypted Prescription",
            data=prescription_content,
            file_name=f"prescription_{patient_id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json",
            mime="application/json"
        )
        
        st.code(prescription_content, language="json")

def show_pharmacy_portal():
    st.header("💊 Pharmacy Portal")
    
    # Pharmacy credentials
    with st.expander("Pharmacy Credentials", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            # Get all available pharmacies from the session state
            available_pharmacies = list(st.session_state.pharmacy_keys.keys())
            
            pharmacy_name = st.selectbox(
                "Pharmacy Name", 
                available_pharmacies,
                index=available_pharmacies.index("Central Pharmacy") if "Central Pharmacy" in available_pharmacies else 0
            )
        
        with col2:
            if st.button("Generate Key Pair"):
                # Retrieve the existing pharmacy user with its keys
                pharmacy_user = st.session_state.pharmacy_keys[pharmacy_name]
                
                # Create a pharmacy portal with the existing user
                st.session_state.pharmacy_portal = PharmacyPortal(pharmacy_user)
                st.session_state.current_pharmacy = pharmacy_name
                st.success(f"Retrieved key pair for {pharmacy_name}")
    
    # Cannot proceed without pharmacy portal
    if not st.session_state.pharmacy_portal:
        st.warning("Please generate a key pair to continue")
        return
    
    # Upload prescription
    st.subheader("Upload Prescription")
    
    uploaded_file = st.file_uploader("Upload encrypted prescription", type=["json"])
    
    if uploaded_file is not None:
        # Read and process prescription
        prescription_content = uploaded_file.read().decode()
        secure_package = json.loads(prescription_content)
        
        # Check if this prescription is for the current pharmacy
        if "target_pharmacy" in secure_package:
            target_pharmacy = secure_package["target_pharmacy"]
            if target_pharmacy != st.session_state.current_pharmacy:
                st.warning(f"⚠️ This prescription was encrypted for {target_pharmacy}, but you're logged in as {st.session_state.current_pharmacy}. Decryption may fail.")
        
        if st.button("Decrypt and Verify Prescription"):
            with st.spinner("Decrypting and verifying prescription..."):
                success, result = st.session_state.pharmacy_portal.decrypt_and_verify_prescription(secure_package)
                
                if success:
                    st.session_state.decrypted_prescription = result
                    st.success("✅ Signature verification successful! Prescription is authentic.")
                else:
                    st.error(f"❌ {result}")
    
    # Display decrypted prescription
    if st.session_state.decrypted_prescription:
        st.subheader("📋 Verified Prescription")
        
        prescription = st.session_state.decrypted_prescription
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**Prescription ID:** {prescription['prescription_id']}")
            st.markdown(f"**Doctor:** {prescription['doctor_name']}")
            st.markdown(f"**Patient:** {prescription['patient_name']} (ID: {prescription['patient_id']})")
            st.markdown(f"**Date Issued:** {prescription['date_issued']}")
        
        with col2:
            st.markdown(f"**Medication:** {prescription['medication']}")
            st.markdown(f"**Dosage:** {prescription['dosage']}")
            st.markdown(f"**Frequency:** {prescription['frequency']}")
            st.markdown(f"**Duration:** {prescription['duration']}")
        
        # Clear button
        if st.button("Clear Prescription"):
            st.session_state.decrypted_prescription = None
            st.experimental_rerun()

def run_demo():
    st.header("🎮 Run Complete Demonstration")
    
    st.write("""
    This is an automated demonstration of the complete workflow:
    1. Key exchange between doctor and pharmacy
    2. Prescription creation by the doctor
    3. Encryption and signing of the prescription
    4. Secure transmission of the prescription
    5. Decryption and verification by the pharmacy
    """)
    
    if st.button("Run Demo"):
        with st.spinner("Running demonstration..."):
            # Step 1: Key Exchange
            st.subheader("🔑 Step 1: Key Exchange")
            
            demo_doctor = User("Dr. Demo", "doctor")
            demo_doctor.generate_key_pair()
            doctor_portal = DoctorPortal(demo_doctor)
            
            demo_pharmacy = User("Demo Pharmacy", "pharmacy")
            demo_pharmacy.generate_key_pair()
            pharmacy_portal = PharmacyPortal(demo_pharmacy)
            
            st.success(f"🏥 Doctor {demo_doctor.name} generated key pair")
            st.success(f"🏪 Pharmacy {demo_pharmacy.name} generated key pair")
            st.success("✅ Public keys exchanged securely")
            
            # Step 2: Doctor creates prescription
            st.subheader("📝 Step 2: Doctor Creates Prescription")
            
            prescription = doctor_portal.create_prescription(
                patient_name="Demo Patient",
                patient_id="DEMO123",
                medication="Ibuprofen",
                dosage="200mg",
                frequency="Twice daily",
                duration="5 days"
            )
            
            st.success("✅ Prescription created")
            
            # Step 3: Encrypt and sign
            st.subheader("🔒 Step 3: Encrypt and Sign Prescription")
            
            secure_package = doctor_portal.encrypt_and_sign_prescription(
                prescription,
                demo_pharmacy.get_public_key()
            )
            
            st.success("✅ Prescription encrypted and signed")
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as f:
                json.dump(secure_package, f, indent=4)
                demo_file = f.name
            
            st.success("✅ Prescription transmitted securely")
            
            # Step 4: Pharmacy decrypts and verifies
            st.subheader("🔓 Step 4: Pharmacy Decrypts and Verifies")
            
            with open(demo_file, 'r') as f:
                received_package = json.load(f)
            
            success, result = pharmacy_portal.decrypt_and_verify_prescription(received_package)
            
            if success:
                st.success("✅ Signature verification successful! Prescription is authentic.")
                
                # Display prescription
                st.subheader("📋 Verified Prescription")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Prescription ID:** {result['prescription_id']}")
                    st.markdown(f"**Doctor:** {result['doctor_name']}")
                    st.markdown(f"**Patient:** {result['patient_name']} (ID: {result['patient_id']})")
                    st.markdown(f"**Date Issued:** {result['date_issued']}")
                
                with col2:
                    st.markdown(f"**Medication:** {result['medication']}")
                    st.markdown(f"**Dosage:** {result['dosage']}")
                    st.markdown(f"**Frequency:** {result['frequency']}")
                    st.markdown(f"**Duration:** {result['duration']}")
            else:
                st.error(f"❌ {result}")
            
            # Cleanup
            try:
                os.unlink(demo_file)
            except:
                pass
        
        st.success("🎉 Demo completed successfully!")

def show_tamper_detection():
    st.header("🔍 Tamper Detection Demonstration")
    
    st.write("""
    This demo shows how the system detects tampering attempts:
    1. A legitimate prescription is created
    2. The prescription is tampered with (modified)
    3. The pharmacy tries to verify the tampered prescription
    4. The system detects the tampering and rejects the prescription
    """)
    
    if st.button("Run Tamper Detection Demo"):
        with st.spinner("Running tampering demonstration..."):
            # Step 1: Key Exchange
            st.subheader("🔑 Step 1: Key Exchange")
            
            demo_doctor = User("Dr. Secure", "doctor")
            demo_doctor.generate_key_pair()
            doctor_portal = DoctorPortal(demo_doctor)
            
            demo_pharmacy = User("Secure Pharmacy", "pharmacy")
            demo_pharmacy.generate_key_pair()
            pharmacy_portal = PharmacyPortal(demo_pharmacy)
            
            st.success(f"🏥 Doctor {demo_doctor.name} generated key pair")
            st.success(f"🏪 Pharmacy {demo_pharmacy.name} generated key pair")
            st.success("✅ Public keys exchanged securely")
            
            # Step 2: Create legitimate prescription
            st.subheader("📝 Step 2: Create Legitimate Prescription")
            
            prescription = doctor_portal.create_prescription(
                patient_name="Jane Smith",
                patient_id="P67890",
                medication="Paracetamol",
                dosage="500mg",
                frequency="3 times daily",
                duration="3 days"
            )
            
            secure_package = doctor_portal.encrypt_and_sign_prescription(
                prescription,
                demo_pharmacy.get_public_key()
            )
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as f:
                json.dump(secure_package, f, indent=4)
                legitimate_file = f.name
            
            st.success("✅ Legitimate prescription created")
            
            # Step 3: Tamper with prescription
            st.subheader("🧪 Step 3: Tamper with Prescription")
            
            with open(legitimate_file, 'r') as f:
                tampered_package = json.load(f)
            
            # Modify the encrypted data
            encrypted_data = base64.b64decode(tampered_package["encrypted_data"])
            # Modify a few bytes to simulate tampering
            if len(encrypted_data) > 10:
                tampered_data = encrypted_data[:5] + b'TAMPERED' + encrypted_data[13:]
                tampered_package["encrypted_data"] = base64.b64encode(tampered_data).decode('utf-8')
            
            # Save tampered prescription
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as f:
                json.dump(tampered_package, f, indent=4)
                tampered_file = f.name
                st.session_state.tampered_file = tampered_file
            
            st.success("✅ Created a tampered prescription file")
            
            # Step 4: Verify tampered prescription
            st.subheader("🔓 Step 4: Attempt to Verify Tampered Prescription")
            
            with open(tampered_file, 'r') as f:
                received_package = json.load(f)
            
            success, result = pharmacy_portal.decrypt_and_verify_prescription(received_package)
            
            if success:
                st.error("❌ WARNING: Tampered prescription was not detected!")
            else:
                st.success("✅ Security system successfully detected tampering!")
                st.error(f"Error message: {result}")
            
            # Cleanup
            try:
                os.unlink(legitimate_file)
            except:
                pass
        
        st.success("🎯 Tampering detection demonstration completed!")
        
        # Download tampered prescription
        if st.session_state.tampered_file:
            with open(st.session_state.tampered_file, 'r') as f:
                tampered_content = f.read()
            
            st.download_button(
                label="Download Tampered Prescription",
                data=tampered_content,
                file_name="tampered_prescription.json",
                mime="application/json"
            )

if __name__ == "__main__":
    main()