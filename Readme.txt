pip install -r ./requirements.txt

docker-compose up -d db

uvicorn main:app   # app will start on port 8000
