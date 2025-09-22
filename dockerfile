FROM python:3.11-slim

WORKDIR /app
COPY . /app

# Instala dependencias Python y SSH server
RUN apt-get update && apt-get install -y openssh-server && \
    pip install --no-cache-dir -r requirements.txt

# Banner (mensaje de bienvenida SSH)
COPY banner.txt /etc/motd

# Crea usuario estándar para login: 'sgi'
RUN useradd -ms /bin/bash sgi && echo 'sgi:sgi' | chpasswd

# Configura SSH para aceptar conexiones y usar el banner
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#Banner none/Banner \/etc\/motd/g' /etc/ssh/sshd_config

# Cambia el shell de sgi para que solo pueda ejecutar tu programa principal
RUN echo 'python /app/main.py' > /home/sgi/.bash_profile

# Exponer puerto SSH
EXPOSE 22

# Por default, ejecuta SSH server
CMD ["/usr/sbin/sshd", "-D"]
