import hashlib
import hmac
import json
import base64
import time
import requests
import platform
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class CGAuth:
    # API configuration constants
    API_URL = "https://cgauth.com/api/v1/"
    YOUR_APP_NAME = "Test"
    API_KEY = "ecc2196cb48f2b3746f93b6ce43f3e0ac3e920235f376b3a3801a8254df91fad"
    API_SECRET = "2271cb904e6c572598b16b0f9dbe4d320b160629ac69b2892344fb1cc244239e"
    SSL_KEY = "95d4c3c7492bafb97174b22cce94ca30628e56d87b82f6df3ba910ccf4c90b92"

    # ========================================================================
    # REQUEST ID GENERATION (NEW)
    # ========================================================================
    
    @staticmethod
    def generate_request_id():
        """
        Generate unique request ID for each authentication attempt
        Prevents replay attacks by ensuring each request is unique
        """
        # Combine timestamp + random bytes for uniqueness
        timestamp = str(int(time.time() * 1000))
        random_bytes = secrets.token_hex(16)
        
        # Hash for consistent length
        combined = timestamp + random_bytes
        return hashlib.sha256(combined.encode()).hexdigest().lower()

    # ========================================================================
    # HWID GENERATION
    # ========================================================================
    
    @staticmethod
    def get_hwid():
        """
        Generate unique hardware ID based on system information
        Uses different methods depending on the operating system
        """
        try:
            hwid = ""
            
            # Windows-specific HWID generation
            if platform.system() == "Windows":
                try:
                    # Try using WMI (Windows Management Instrumentation) first
                    import wmi
                    c = wmi.WMI()
                    
                    # Collect processor ID
                    for processor in c.Win32_Processor():
                        hwid += str(processor.ProcessorId or "")
                    
                    # Collect motherboard serial number
                    for board in c.Win32_BaseBoard():
                        hwid += str(board.SerialNumber or "")
                    
                    # Collect BIOS serial number
                    for bios in c.Win32_BIOS():
                        hwid += str(bios.SerialNumber or "")
                except:
                    # Fallback method using WMIC command line
                    import subprocess
                    try:
                        cpu = subprocess.check_output("wmic cpu get processorid", shell=True).decode()
                        hwid += cpu.split('\n')[1].strip()
                    except:
                        pass
            else:
                # Linux/Unix-based HWID generation
                import subprocess
                try:
                    hwid = subprocess.check_output("cat /proc/cpuinfo | grep Serial", shell=True).decode()
                except:
                    pass
            
            # Clean up the HWID string (remove spaces, dashes, underscores)
            hwid = hwid.replace(" ", "").replace("-", "").replace("_", "").upper()
            
            # Validate that we successfully generated an HWID
            if not hwid:
                raise Exception("Failed to generate HWID")
            
            # Hash the HWID using SHA256 for consistency and anonymization
            return hashlib.sha256(hwid.encode()).hexdigest().upper()
            
        except:
            # Ultimate fallback: use hostname + username as HWID base
            import socket
            import getpass
            fallback = socket.gethostname() + getpass.getuser()
            return hashlib.sha256(fallback.encode()).hexdigest().upper()

    # ========================================================================
    # ENCRYPTION/DECRYPTION
    # ========================================================================
    
    @staticmethod
    def encrypt_payload(params):
        """
        Encrypt payload using AES-256-CBC encryption
        This ensures data security during transmission
        """
        # Convert parameters to JSON string
        json_str = json.dumps(params)
        
        # Derive 256-bit encryption key from API secret
        key = hashlib.sha256(CGAuth.API_SECRET.encode()).digest()
        
        # Generate random initialization vector (IV) for CBC mode
        iv = get_random_bytes(16)
        
        # Create AES cipher in CBC mode
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the data to match AES block size and encrypt
        encrypted = cipher.encrypt(pad(json_str.encode(), AES.block_size))
        
        # Combine IV and encrypted data (IV is needed for decryption)
        combined = iv + encrypted
        
        # Encode to base64 for safe transmission
        return base64.b64encode(combined).decode()
    
    @staticmethod
    def decrypt_payload(encrypted):
        """
        Decrypt AES-256-CBC encrypted payload
        Reverses the encryption process
        """
        # Decode from base64
        data = base64.b64decode(encrypted)
        
        # Extract IV (first 16 bytes) and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        # Derive the same encryption key from API secret
        key = hashlib.sha256(CGAuth.API_SECRET.encode()).digest()
        
        # Create AES cipher with the extracted IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and remove padding
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return decrypted.decode()

    # ========================================================================
    # HMAC VERIFICATION (UPDATED)
    # ========================================================================
    
    @staticmethod
    def verify_hmac(data, received_hmac, request_id):
        """
        Verify HMAC signature with request binding to ensure data integrity
        This prevents tampering and replay attacks
        """
        # Combine data + request_id for HMAC calculation
        combined = data + request_id
        
        # Compute HMAC-SHA256 of the combined data
        computed = hmac.new(
            CGAuth.API_SECRET.encode(),
            combined.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Compare computed HMAC with received HMAC (case-insensitive)
        return computed.lower() == received_hmac.lower()

    # ========================================================================
    # AUTHENTICATION - WITH REPLAY ATTACK PROTECTION
    # ========================================================================
    
    @staticmethod
    def auth_license(license_key, hwid):
        """
        Authenticate using a license key with replay attack protection
        """
        try:
            # ✅ Generate unique request ID
            request_id = CGAuth.generate_request_id()
            
            # ✅ Prepare authentication parameters with request_id and timestamp
            params = {
                "api_secret": CGAuth.API_SECRET,
                "type": "license",
                "key": license_key,
                "hwid": hwid,
                "request_id": request_id,  # NEW
                "timestamp": str(int(time.time()))  # NEW
            }
            
            # Encrypt the payload for secure transmission
            encrypted = CGAuth.encrypt_payload(params)
            
            # Set headers to bypass Cloudflare protection
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin"
            }
            
            # Use a session to maintain cookies and connection state
            session = requests.Session()
            
            # Send POST request to the API
            response = session.post(
                CGAuth.API_URL,
                data={
                    "api_key": CGAuth.API_KEY,
                    "payload": encrypted
                },
                headers=headers,
                timeout=15,
                verify=True
            )
            
            # Check HTTP status code
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}"
                }
            
            # Check if Cloudflare protection is blocking the request
            if "checking your browser" in response.text.lower() or "cloudflare" in response.text.lower():
                return {
                    "success": False,
                    "error": "Cloudflare protection detected"
                }
            
            # Parse JSON response
            try:
                json_response = response.json()
            except json.JSONDecodeError as je:
                return {
                    "success": False,
                    "error": f"Invalid JSON response: {str(je)}"
                }
            
            # Validate response structure
            if "data" not in json_response or "hmac" not in json_response or "timestamp" not in json_response:
                return {
                    "success": False,
                    "error": f"Invalid response structure: {json_response}"
                }
            
            # Extract response components
            enc_data = json_response["data"]
            received_hmac = json_response["hmac"]
            timestamp = json_response["timestamp"]
            
            # ✅ Verify timestamp (stricter: 2 minutes tolerance)
            if abs(int(time.time()) - timestamp) > 120:
                return {
                    "success": False,
                    "error": "Response expired"
                }
            
            # ✅ Verify HMAC with request_id binding
            if not CGAuth.verify_hmac(enc_data, received_hmac, request_id):
                return {
                    "success": False,
                    "error": "HMAC verification failed - possible replay attack"
                }
            
            # Decrypt the response data
            decrypted = CGAuth.decrypt_payload(enc_data)
            result = json.loads(decrypted)
            
            # ✅ Verify request_id in response matches our request
            response_request_id = result.get("request_id")
            if response_request_id and response_request_id != request_id:
                return {
                    "success": False,
                    "error": "Request ID mismatch - possible replay attack"
                }
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Network error: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error: {str(e)}"
            }
    
    @staticmethod
    def auth_user(username, password, hwid):
        """
        Authenticate using username and password with replay attack protection
        """
        try:
            # ✅ Generate unique request ID
            request_id = CGAuth.generate_request_id()
            
            # ✅ Prepare authentication parameters with request_id and timestamp
            params = {
                "api_secret": CGAuth.API_SECRET,
                "type": "user",
                "key": username,
                "password": password,
                "hwid": hwid,
                "request_id": request_id,  # NEW
                "timestamp": str(int(time.time()))  # NEW
            }
            
            # Encrypt the payload for secure transmission
            encrypted = CGAuth.encrypt_payload(params)
            
            # Set headers to bypass Cloudflare protection
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive"
            }
            
            # Use a session to maintain cookies and connection state
            session = requests.Session()
            
            # Send POST request to the API
            response = session.post(
                CGAuth.API_URL,
                data={
                    "api_key": CGAuth.API_KEY,
                    "payload": encrypted
                },
                headers=headers,
                timeout=15,
                verify=True
            )
            
            # Check HTTP status code
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}"
                }
            
            # Check if Cloudflare protection is blocking the request
            if "cloudflare" in response.text.lower():
                return {
                    "success": False,
                    "error": "Cloudflare protection detected"
                }
            
            # Parse JSON response
            try:
                json_response = response.json()
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "error": "Invalid JSON response"
                }
            
            # Validate response structure
            if "data" not in json_response or "hmac" not in json_response:
                return {
                    "success": False,
                    "error": "Invalid response structure"
                }
            
            # Extract response components
            enc_data = json_response["data"]
            received_hmac = json_response["hmac"]
            timestamp = json_response["timestamp"]
            
            # ✅ Verify timestamp (stricter: 2 minutes tolerance)
            if abs(int(time.time()) - timestamp) > 120:
                return {
                    "success": False,
                    "error": "Response expired"
                }
            
            # ✅ Verify HMAC with request_id binding
            if not CGAuth.verify_hmac(enc_data, received_hmac, request_id):
                return {
                    "success": False,
                    "error": "HMAC verification failed - possible replay attack"
                }
            
            # Decrypt the response data
            decrypted = CGAuth.decrypt_payload(enc_data)
            result = json.loads(decrypted)
            
            # ✅ Verify request_id in response matches our request
            response_request_id = result.get("request_id")
            if response_request_id and response_request_id != request_id:
                return {
                    "success": False,
                    "error": "Request ID mismatch - possible replay attack"
                }
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": f"Network error: {str(e)}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error: {str(e)}"
            }