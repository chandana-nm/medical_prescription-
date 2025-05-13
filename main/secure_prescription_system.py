# Secure Medical Prescription Transmission System
# Requirements: pip install pycryptodome

import os
import json
import base64
import datetime
import hashlib
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
            "doctor_public_key": self.doctor.get_public_key()
        }
        
        return secure_package
    
    def save_secure_package(self, secure_package, filename="prescription_package.json"):
        """Save the secure package to a file"""
        with open(filename, 'w') as f:
            json.dump(secure_package, f, indent=4)
        print(f"Secure prescription saved to {filename}")

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
                print("✅ Signature verification successful! Prescription is authentic.")
                
                # Convert JSON back to dictionary
                prescription_dict = json.loads(prescription_json)
                
                # Store verified prescription
                self.prescriptions[prescription_dict["prescription_id"]] = prescription_dict
                
                return prescription_dict
                
            except (ValueError, TypeError) as e:
                print("❌ Signature verification failed! Prescription might be tampered.")
                print(f"Error: {e}")
                return None
                
        except Exception as e:
            print(f"❌ Error processing prescription: {e}")
            return None
    
    def load_secure_package(self, filename="prescription_package.json"):
        """Load a secure package from a file"""
        try:
            with open(filename, 'r') as f:
                secure_package = json.load(f)
            return secure_package
        except Exception as e:
            print(f"❌ Error loading secure package: {e}")
            return None
    
    def display_prescription(self, prescription_dict):
        """Display the prescription in a formatted way"""
        if not prescription_dict:
            print("No valid prescription to display.")
            return
            
        print("\n" + "="*50)
        print(f"📋 PRESCRIPTION #{prescription_dict['prescription_id']}")
        print("="*50)
        print(f"🩺 Doctor: {prescription_dict['doctor_name']}")
        print(f"👤 Patient: {prescription_dict['patient_name']} (ID: {prescription_dict['patient_id']})")
        print(f"💊 Medication: {prescription_dict['medication']}")
        print(f"📝 Dosage: {prescription_dict['dosage']}")
        print(f"⏱️ Frequency: {prescription_dict['frequency']}")
        print(f"📅 Duration: {prescription_dict['duration']}")
        print(f"🕒 Date Issued: {prescription_dict['date_issued']}")
        print("="*50)

def key_exchange_simulation():
    """Simulate a key exchange between doctor and pharmacy"""
    # In a real system, this would involve a secure key exchange protocol
    # like Diffie-Hellman or using a certificate authority
    print("🔑 Simulating secure key exchange...")
    
    doctor_user = User("Dr. Smith", "doctor")
    doctor_user.generate_key_pair()
    doctor_portal = DoctorPortal(doctor_user)
    
    pharmacy_user = User("Central Pharmacy", "pharmacy")
    pharmacy_user.generate_key_pair()
    pharmacy_portal = PharmacyPortal(pharmacy_user)
    
    print(f"🏥 Doctor {doctor_user.name} generated key pair")
    print(f"🏪 Pharmacy {pharmacy_user.name} generated key pair")
    print("✅ Public keys exchanged securely\n")
    
    return doctor_portal, pharmacy_portal

def run_demo():
    """Run a demonstration of the system"""
    print("="*70)
    print("🔐 SECURE MEDICAL PRESCRIPTION TRANSMISSION SYSTEM 🔐")
    print("="*70)
    
    # Step 1: Key Exchange
    doctor_portal, pharmacy_portal = key_exchange_simulation()
    
    # Step 2: Doctor creates, encrypts, and signs a prescription
    print("\n📝 DOCTOR PORTAL: Creating a new prescription...")
    prescription = doctor_portal.create_prescription(
        patient_name="John Doe",
        patient_id="P12345",
        medication="Amoxicillin",
        dosage="500mg",
        frequency="3 times daily",
        duration="7 days"
    )
    print("✅ Prescription created")
    
    print("\n🔒 Encrypting and signing prescription...")
    secure_package = doctor_portal.encrypt_and_sign_prescription(
        prescription,
        pharmacy_portal.pharmacy.get_public_key()
    )
    print("✅ Prescription encrypted and signed")
    
    # Save the secure package to simulate transmission
    doctor_portal.save_secure_package(secure_package)
    print("✅ Prescription transmitted securely")
    
    # Step 3: Pharmacy receives, decrypts, and verifies the prescription
    print("\n📥 PHARMACY PORTAL: Receiving prescription...")
    received_package = pharmacy_portal.load_secure_package()
    
    if received_package:
        print("✅ Prescription package received")
        
        print("\n🔓 Decrypting and verifying prescription...")
        decrypted_prescription = pharmacy_portal.decrypt_and_verify_prescription(received_package)
        
        if decrypted_prescription:
            print("\n📋 Displaying verified prescription:")
            pharmacy_portal.display_prescription(decrypted_prescription)
    
    print("\n" + "="*70)
    print("🎉 Demo completed successfully!")
    print("="*70)

def tamper_simulation():
    """Simulate a tampering attempt to demonstrate the security features"""
    print("\n\n" + "="*70)
    print("🔍 TAMPERING DETECTION DEMONSTRATION")
    print("="*70)
    
    # Step 1: Key Exchange
    doctor_portal, pharmacy_portal = key_exchange_simulation()
    
    # Step 2: Doctor creates a legitimate prescription
    prescription = doctor_portal.create_prescription(
        patient_name="Jane Smith",
        patient_id="P67890",
        medication="Ibuprofen",
        dosage="400mg",
        frequency="2 times daily",
        duration="5 days"
    )
    
    secure_package = doctor_portal.encrypt_and_sign_prescription(
        prescription, 
        pharmacy_portal.pharmacy.get_public_key()
    )
    doctor_portal.save_secure_package(secure_package, "legitimate_prescription.json")
    
    # Step 3: Simulate tampering - modify the encrypted data
    print("\n🧪 Simulating tampering with the prescription...")
    with open("legitimate_prescription.json", 'r') as f:
        tampered_package = json.load(f)
    
    # Modify the encrypted data (this will cause verification to fail)
    encrypted_data = base64.b64decode(tampered_package["encrypted_data"])
    # Modify a few bytes to simulate tampering
    if len(encrypted_data) > 10:
        tampered_data = encrypted_data[:5] + b'TAMPERED' + encrypted_data[13:]
        tampered_package["encrypted_data"] = base64.b64encode(tampered_data).decode('utf-8')
    
    with open("tampered_prescription.json", 'w') as f:
        json.dump(tampered_package, f, indent=4)
    print("✅ Created a tampered prescription file")
    
    # Step 4: Pharmacy tries to verify the tampered prescription
    print("\n📥 PHARMACY PORTAL: Processing tampered prescription...")
    tampered_package = pharmacy_portal.load_secure_package("tampered_prescription.json")
    
    if tampered_package:
        print("\n🔓 Attempting to decrypt and verify tampered prescription...")
        decrypted_prescription = pharmacy_portal.decrypt_and_verify_prescription(tampered_package)
        
        if decrypted_prescription:
            print("❌ WARNING: Tampered prescription was not detected!")
        else:
            print("✅ Security system successfully detected tampering!")
    
    print("\n" + "="*70)
    print("🎯 Tampering detection demonstration completed!")
    print("="*70)

def run_system():
    """Run the complete system with menu options"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n" + "="*70)
    print("🏥 SECURE MEDICAL PRESCRIPTION SYSTEM 🏥")
    print("="*70)
    
    while True:
        print("\nSelect an option:")
        print("1. Run complete demonstration")
        print("2. Run tampering detection demonstration")
        print("3. Create custom prescription")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == '1':
            run_demo()
        elif choice == '2':
            tamper_simulation()
        elif choice == '3':
            create_custom_prescription()
        elif choice == '4':
            print("\nExiting system. Goodbye!")
            break
        else:
            print("\n❌ Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")
        os.system('cls' if os.name == 'nt' else 'clear')

def create_custom_prescription():
    """Allow the user to create a custom prescription"""
    print("\n" + "="*70)
    print("📝 CREATE CUSTOM PRESCRIPTION")
    print("="*70)
    
    # Collect prescription information
    doctor_name = input("\nEnter doctor's name: ")
    patient_name = input("Enter patient's name: ")
    patient_id = input("Enter patient ID: ")
    medication = input("Enter medication: ")
    dosage = input("Enter dosage: ")
    frequency = input("Enter frequency: ")
    duration = input("Enter duration: ")
    
    # Create doctor and pharmacy
    doctor_user = User(doctor_name, "doctor")
    doctor_user.generate_key_pair()
    doctor_portal = DoctorPortal(doctor_user)
    
    pharmacy_name = input("\nEnter pharmacy name: ")
    pharmacy_user = User(pharmacy_name, "pharmacy")
    pharmacy_user.generate_key_pair()
    pharmacy_portal = PharmacyPortal(pharmacy_user)
    
    # Create and process prescription
    prescription = doctor_portal.create_prescription(
        patient_name=patient_name,
        patient_id=patient_id,
        medication=medication,
        dosage=dosage,
        frequency=frequency,
        duration=duration
    )
    
    # Encrypt and sign
    print("\n🔒 Encrypting and signing prescription...")
    secure_package = doctor_portal.encrypt_and_sign_prescription(
        prescription,
        pharmacy_portal.pharmacy.get_public_key()
    )
    
    custom_filename = f"prescription_{patient_id}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
    doctor_portal.save_secure_package(secure_package, custom_filename)
    
    # Verify and display
    print(f"\n📥 Loading prescription from {custom_filename}...")
    received_package = pharmacy_portal.load_secure_package(custom_filename)
    
    if received_package:
        print("\n🔓 Decrypting and verifying prescription...")
        decrypted_prescription = pharmacy_portal.decrypt_and_verify_prescription(received_package)
        
        if decrypted_prescription:
            print("\n📋 Displaying verified prescription:")
            pharmacy_portal.display_prescription(decrypted_prescription)

if __name__ == "__main__":
    run_system()