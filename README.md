# fusionauth-avatar-extension
</br>A avatar management api for fusionauth made with fastapi and cloudflare kv.
</br>Cloudflare KV is used to store emails => avatar tokens instead of md5 which is more privacy secure.


# Setup

</br>To setup for Cloudflare Workers branch:
</br>Coming Soon

</br>It is reccomended to use docker-compose to setup.
</br>Download and place https://tea.t2v.ch/t2v/avatar-fusionauth-plugin/src/branch/workers/docker-compose.yml in your working directory 
</br>Fill out the enviroment variables in the docker-compose.yml file
</br>Run docker-compose up -d
</br>Forward a domain to port 8080 and 80

-> Instructions for Fusionauth webhooks coming soon <-


# LEGACY INSTALL

To setup for FastAPI brnach:
</br>Install Python 3.10 or newer
</br>Clone the repo
</br>Run pip install -r requirements.txt
</br>Change the .env to your requirements
</br>Install chosen webserver
</br>Point webserver to port 8081
