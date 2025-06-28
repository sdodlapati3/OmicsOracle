import json
import os
import sys

# Print all environment variables
env_vars = {k: v for k, v in os.environ.items() if not k.startswith("_")}
print(json.dumps(env_vars, indent=2))

# Check specifically for NCBI_EMAIL
ncbi_email = os.environ.get("NCBI_EMAIL")
if ncbi_email:
    print(f"\nNCBI_EMAIL is correctly set to: {ncbi_email}")
else:
    print("\nNCBI_EMAIL is NOT set!")
    sys.exit(1)
