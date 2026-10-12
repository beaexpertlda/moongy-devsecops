# moongy-devsecops

Principais Vulnerabilidades Presentes neste Código:
SQL Injection (/login): A construção da query faz-se por interpolação direta de variáveis (${username}), permitindo contornar a autenticação injetando comandos SQL (ex: ' OR '1'='1).

Reflected XSS (/search): O parâmetro q é devolvido diretamente no corpo da resposta HTTP sem codificação de carateres especiais, permitindo a execução de scripts arbitrários no browser da vítima.

Command Injection (/ping): O parâmetro ip é concatenado diretamente na função exec(), permitindo que um atacante execute comandos no sistema operativo hospedeiro (ex: ; cat /etc/passwd).

Segredos em Hardcode (JWT_SECRET): Credenciais e chaves criptográficas sensíveis estão expostas diretamente no código-fonte.

Dependências Vulneráveis (package.json): Utiliza versões antigas de pacotes do npm que contêm vulnerabilidades conhecidas (CVEs registadas).
