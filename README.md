# 📊 Log Analyzer Pro

Log Analyzer Pro — это мощный анализатор веб-логов на базе Streamlit + SQLite для быстрого исследования трафика, ботов, URL, IP-адресов и поведения пользователей.

Подходит для:
- SEO-специалистов
- DevOps
- системных администраторов
- аналитики серверных логов
- анализа поисковых ботов Google/Yandex/Bing/Ahrefs/Semrush

---

# 🚀 Возможности

## ✅ Импорт логов
- Быстрая загрузка `.log` файлов
- Батчевый импорт в SQLite
- WAL режим для высокой скорости
- Поддержка больших логов

---

## 🔍 Конструктор SQL-фильтров
Визуальный builder условий через:
- URL
- User-Agent
- IP
- Referer
- Status Code
- Тип трафика
- Domain

Поддерживаются:
- Contains
- Equals
- AND / OR
- LIKE фильтрация

---

## 📈 Аналитика трафика
- Графики запросов по времени
- Топ URL
- Количество запросов
- Уникальные IP

---

## 🕷️ Анализ ботов
Автоматическое определение:
- Googlebot
- YandexBot
- Bingbot
- AhrefsBot
- SemrushBot
- DotBot
- MJ12Bot
- других crawler/spider bot

Для каждого бота:
- User-Agent
- IP
- динамика посещений
- количество hits

---

## 📄 Просмотр сырых данных
- SQL WHERE отображение
- DataFrame таблица
- последние запросы
- фильтрация в реальном времени

---

# ⚙️ Технологии

- Python
- Streamlit
- SQLite
- Pandas
- Regex Parsing
- streamlit-condition-tree

---

# 📦 Установка

## 1. Клонирование репозитория

```bash
git clone https://github.com/yourusername/log-analyzer-pro.git
cd log-analyzer-pro
