import os, requests

def get_forecast(city):
    api_key = os.environ["WEATHER_API_KEY"]
    return requests.get("https://api.weather-provider.tld/v1/forecast", params={"city": city, "key": api_key})
