# fusionauth-avatar-extension
A avatar management api for fusionauth made with fastapi and cloudflare kv.
Cloudflare KV is used to store emails => avatar tokens instead of md5 which is more privacy secure.


# Setup

To setup for Cloudflare Workers branch:
Coming Soon

It is reccomended to use docker-compose to setup.
Just git clone the repository,
Fill out the .env.example
Run docker-compose up -d

-> Instructions for Fusionauth webhooks coming soon <-


# LEGACY INSTALL

To setup for FastAPI brnach:
</br>Install Python 3.10 or newer
</br>Clone the repo
</br>Run pip install -r requirements.txt
</br>Change the .env to your requirements
</br>Install chosen webserver
</br>Point webserver to port 8081
