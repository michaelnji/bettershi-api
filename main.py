from fastapi import FastAPI


app = FastAPI()


# for server health
@app.get('/status')
def get_status() -> str:
	return 'App is running well. Exchange rates provided by Fapshi (https://fapshi.com)'
