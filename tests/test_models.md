from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    base_url='https://integrate.api.nvidia.com/v1',
    api_key=os.environ['NVIDIA_API_KEY']
)

candidates = [
    'mistralai/mistral-large-2-instruct',
    'mistralai/mistral-large',
    'mistralai/mixtral-8x22b-v0.1',
    'z-ai/glm-5.3',
    'z-ai/glm-5.3-flash',
    'moonshotai/kimi-k2.6',
    'nvidia/llama-3.1-nemotron-51b-instruct',
    'nvidia/nemotron-4-340b-instruct',
]

for model in candidates:
    try:
        r = client.chat.completions.create(
            model=model,
            max_tokens=10,
            messages=[{'role': 'user', 'content': 'Say OK'}]
        )
        print(f'WORKS   {model}  ->  {r.choices[0].message.content!r}')
    except Exception as e:
        msg = str(e)[:80]
        print(f'FAILED  {model}  ->  {msg}')