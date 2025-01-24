import streamlit as st
import requests
import json
import plotly.graph_objects as go

HF_TOKEN = "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"
MODEL_NAME = "DunnBC22/codebert-base-Malicious_URLs"
API_URL = f"https://api-inference.huggingface.co/models/{MODEL_NAME}"

HEADERS = {"Authorization": f"Bearer {HF_TOKEN}"}

# Словарь для перевода меток модели на русский
LABEL_TRANSLATE = {
    "benign": "Безопасный",
    "defacement": "Дефейс / Вандализм",
    "phishing": "Фишинг",
    "malware": "Вредоносное ПО",
}


def query_url(url_text):
    """Делаем POST-запрос к HF Inference API."""
    data = {"inputs": url_text}
    response = requests.post(API_URL, headers=HEADERS, json=data)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.text}


st.title("Проверка URL через Hugging Face API")

url_input = st.text_input("Введите URL для анализа", "https://example.com")

if st.button("Проверить"):
    results = query_url(url_input)

    # Проверяем, нет ли ошибки (или модель не прогрузилась)
    if isinstance(results, dict) and "error" in results:
        st.error(f"Ошибка: {results['error']}")
    else:
        # Посмотрим, что именно вернулось
        # st.write("**RAW response:**", results)

        # Если ответ в формате [[{...}]], "распакуем" внутренний список
        if len(results) > 0 and isinstance(results[0], list):
            results = results[0]

        # Теперь results — список словарей вида [{"label": "...", "score": 0.x}, ...]
        st.write("**Результаты анализа:**")

        # Подготовим данные для вывода и для графика
        labels_ru = []
        scores = []

        for item in results:
            label_en = item.get("label")
            score = item.get("score", 0.0)

            # Переводим метку на русский, если она есть в словаре
            label_ru = LABEL_TRANSLATE.get(label_en, label_en)

            st.write(f"- **{label_ru}** — {score:.2f}")

            labels_ru.append(label_ru)
            scores.append(score)

        # Построим горизонтальную гистограмму с Plotly
        fig = go.Figure(data=[
            go.Bar(x=scores,
                   y=labels_ru,
                   orientation='h',
                   text=[f"{(s*100):.2f}%" for s in scores],
                   textposition='auto')
        ])
        fig.update_layout(title="Гистограмма оценок",
                          xaxis_title="Score",
                          yaxis_title="Тип угрозы")

        st.plotly_chart(fig, use_container_width=True)
