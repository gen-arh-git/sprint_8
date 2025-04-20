# Сдача проектной работы 8 спринта.

Источник https://github.com/Yandex-Practicum/architecture-sprint-8

Необходимо улучшить безопасность приложения.
Подготовить API для работы с отчётом.

## Проверка

 - Запусть Docker Desktop
 - Загрузить текущий проект из репозитария
 - Выполнить docker-compose up -d --build
 - Открыть frontdend http://localhost:3000/
 - Выполнить авторизацю с ролью prothetic_user. Например, prothetic1/prothetic123
 - Нажать кнопку "Download Report" 
 - Исследовать статус 200 
![image] [./2025-04-20_12-52-13.png]
 - Выполнить restart Docker Desktop
 - Открыть frontdend http://localhost:3000/
 - Выполнить авторизацю с ролью user. Например, user1/password123
 - Нажать кнопку "Download Report" 
 - Исследовать статус 401
![image] [./2025-04-20_12-54-47.png]
 