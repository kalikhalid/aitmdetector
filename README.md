# Project: Deticting AiTM

## 📌 Обзор проекта

Проект состоит из двух основных компонентов:

1. *API* `(api/)` — Веб-сервер на Rust (Axum), анализирующий URL на признаки фишинга (подозрительные TLS-сертификаты, возраст домена, структуру URL).
2. *Бот* `(bot/)` — Автономный сервис, взаимодействующий с API для мониторинга и обработки данных.

Цель: Обнаружение атак типа *AiTM (Adversary-in-The-Middle)* и фишинговых страниц, имитирующих легитимные сервисы (например, Evilginx).

## ⚙ Установка и запуск
*1. Требования*
    - Docker и Docker Compose
    - API-ключ SecurityTrails (для данных о доменах)
    - Rust (если запуск без Docker)

*2. Запуск через Docker*
```bash
# 1. Клонируйте репозиторий
git clone <repo>
cd <проект>

# 2. Запустите сервисы
docker-compose up --build
```
Сервисы будут доступны:
- API: http://localhost:8080
- Бот: Запущен в фоне (логи через docker logs rust_bot).

## 🌐API Endpoints
#### 🔍 Проверка URL на фишинг

**Запрос:**
```
POST /api/detect/{url}
```
**Пример:**
```bash
curl -X POST "http://localhost:8080/api/detect/https%3A%2F%2Fevil.example.com"
```
**Ответ:**
```json
{
  "url_structure": {"status": "detected", "message": "suspicious URL structure"},
  "tls_data": {"status": "detected", "message": "suspicious certs (Let's Encrypt)"},
  "domain_age": {"status": "detected", "message": "domain age < 30 days"},
  "main_page": {"status": "not_detected"}
}
```
#### Параметры проверки

1. Структура URL: Анализ подозрительных паттернов (например, evilginx-подобные пути).

2. TLS-сертификаты: Поиск сертификатов Let's Encrypt (часто используются в фишинге).

3. Возраст домена: Домены младше 30 дней считаются подозрительными.

4. Главная страница: Проверка, возвращает ли домен HTTP 200.


