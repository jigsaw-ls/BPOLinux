#!/bin/bash

# Crear la carpeta resultados si no existe
mkdir -p resultados

# Archivo de salida con el informe
output_file="resultados/auditoria_seguridad_ubuntu.txt"
current_date=$(date '+%Y-%m-%d %H:%M:%S')

# Función para mostrar un logotipo en ASCII
show_logo() {
    echo "======================================================" 
    echo "             _                _                        " 
    echo "            | |              (_)                       "
    echo "         ___| |__   ___   ___ _  __ _ _ __   __ _ ___  "
    echo "        / __| '_ \ / _ \ / __| |/ _\` | '_ \ / _\` / __| "
    echo "        \__ \ | | | (_) | (__| | (_| | | | | (_| \__ \ "
    echo "        |___/_| |_|\___/ \___|_|\__, |_| |_|\__,_|___/ "
    echo "                                __/ |                 "
    echo "                               |___/                  "
    echo "         Desarrollado por GENETEC S.A.                "
    echo "======================================================" 
}

# Llamada a la función para mostrar el logo en el inicio
show_logo

# Función para agregar encabezados a secciones
add_section() {
    echo -e "\n------------------------------------------------------" >> $output_file
    echo -e "$1" >> $output_file
    echo -e "------------------------------------------------------" >> $output_file
}

# Función para animación de carga
loading_animation() {
    local -r pid="${1}"
    local -r delay='0.25'
    local spinstr='|/-\'
    echo -n "Procesando"
    while [ "$(ps a | awk '{print $1}' | grep ${pid})" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=${temp}${spinstr%"$temp"}
        sleep ${delay}
        printf "\b\b\b\b\b\b"
    done
    echo ""
}

# Ejecución del análisis con animación de carga
echo "Iniciando auditoría de seguridad..."
echo "Esto puede tardar un momento..."

# Simulación de procesos largos con animación de carga
(sleep 5) &
loading_animation $!

# Archivo de salida
echo "------------------------------------------------------" >> $output_file
echo "         AUDITORÍA DE SEGURIDAD DEL SISTEMA UBUNTU     " >> $output_file
echo "======================================================" >> $output_file
echo "Fecha de la Auditoría: $current_date" >> $output_file
echo "Auditoría realizada en: $(hostname)" >> $output_file
echo "------------------------------------------------------" >> $output_file

# 1. Información General del Sistema
add_section "1. Información General del Sistema"
{
    echo "Sistema Operativo: $(lsb_release -d | awk -F"\t" '{print $2}')"
    echo "Versión del Kernel: $(uname -r)"
    echo "Arquitectura del Sistema: $(uname -m)"
} >> $output_file

# Simulación de proceso largo
(sleep 2) &
loading_animation $!

# 2. Verificación del Estado del Firewall (UFW)
add_section "2. Configuración del Firewall"
ufw_status=$(sudo ufw status | grep -w "Status: active")
if [ -z "$ufw_status" ]; then
    {
        echo "CRÍTICO: Firewall (UFW) está desactivado."
        echo "Problema Potencial: El sistema está expuesto a ataques externos."
        echo "Recomendación: Activa el firewall con 'sudo ufw enable'."
    } >> $output_file
else
    echo "OK: Firewall (UFW) está activado." >> $output_file
fi

# Simulación de proceso largo
(sleep 2) &
loading_animation $!

# 3. Estado de Seguridad de Aplicaciones (AppArmor)
add_section "3. Estado de Seguridad de Aplicaciones (AppArmor)"
apparmor_status=$(sudo aa-status | grep "profiles are loaded")
if [ -z "$apparmor_status" ]; then
    {
        echo "CRÍTICO: AppArmor no está activo."
        echo "Problema Potencial: Las aplicaciones no están limitadas por perfiles de seguridad."
        echo "Recomendación: Activa AppArmor con 'sudo systemctl start apparmor'."
    } >> $output_file
else
    echo "OK: AppArmor está activo." >> $output_file
fi

# Simulación de proceso largo
(sleep 2) &
loading_animation $!

# 4. Verificación de Actualizaciones del Sistema
add_section "4. Actualizaciones del Sistema"
sudo apt update > /dev/null 2>&1
updates=$(apt list --upgradable 2> /dev/null | grep -v "Listing" | wc -l)
if [ "$updates" -gt 0 ]; then
    {
        echo "CRÍTICO: Hay $updates paquetes pendientes de actualización."
        echo "Problema Potencial: Vulnerabilidades de seguridad conocidas."
        echo "Recomendación: Ejecuta 'sudo apt upgrade' para instalar las actualizaciones."
    } >> $output_file
else
    echo "OK: El sistema está completamente actualizado." >> $output_file
fi

# 5. Verificación de Permisos en Archivos Críticos
add_section "5. Permisos de Archivos Críticos"
{
    shadow_perms=$(stat -c "%a" /etc/shadow)
    if [ "$shadow_perms" != "600" ]; then
        echo "CRÍTICO: Permisos incorrectos en /etc/shadow ($shadow_perms)." >> $output_file
        echo "Problema Potencial: Permisos incorrectos pueden permitir acceso no autorizado." >> $output_file
        echo "Recomendación: Ejecuta 'sudo chmod 600 /etc/shadow' para corregir los permisos." >> $output_file
    else
        echo "OK: Permisos de /etc/shadow son correctos (600)." >> $output_file
    fi

    passwd_perms=$(stat -c "%a" /etc/passwd)
    if [ "$passwd_perms" != "644" ]; then
        echo "CRÍTICO: Permisos incorrectos en /etc/passwd ($passwd_perms)." >> $output_file
        echo "Problema Potencial: Modificación no autorizada de información de cuentas." >> $output_file
        echo "Recomendación: Ejecuta 'sudo chmod 644 /etc/passwd' para corregir los permisos." >> $output_file
    else
        echo "OK: Permisos de /etc/passwd son correctos (644)." >> $output_file
    fi
} >> $output_file

# 6. Verificación de Ataques por Fuerza Bruta (fail2ban)
add_section "6. Detección de Ataques por Fuerza Bruta"
fail2ban_status=$(sudo systemctl is-active fail2ban)
if [ "$fail2ban_status" != "active" ]; then
    {
        echo "CRÍTICO: fail2ban no está activo."
        echo "Problema Potencial: El sistema está en riesgo de ataques de fuerza bruta."
        echo "Recomendación: Activa fail2ban con 'sudo systemctl start fail2ban'."
    } >> $output_file
else
    echo "OK: fail2ban está activo." >> $output_file
fi

# Simulación de proceso largo
(sleep 2) &
loading_animation $!

# 7. Análisis de Registros de Acceso
add_section "7. Análisis de Registros de Acceso"
echo "Verificando registros de acceso recientes..." >> $output_file
logins=$(last -n 10)
if [ -z "$logins" ]; then
    echo "Advertencia: No se encontraron registros de acceso recientes." >> $output_file
else
    echo "Registros de acceso recientes:" >> $output_file
    echo "$logins" >> $output_file
fi

# 8. Verificación de la Configuración de SSH
add_section "8. Configuración de SSH"
ssh_config="/etc/ssh/sshd_config"
if [ -f "$ssh_config" ]; then
    {
        echo "Verificando configuración de SSH..."
        PermitRootLogin=$(grep "^PermitRootLogin" $ssh_config | awk '{print $2}')
        PasswordAuthentication=$(grep "^PasswordAuthentication" $ssh_config | awk '{print $2}')
        
        if [[ "$PermitRootLogin" == "yes" ]]; then
            echo "CRÍTICO: El acceso de root por SSH está permitido." >> $output_file
            echo "Problema Potencial: Esto puede facilitar ataques de fuerza bruta." >> $output_file
            echo "Recomendación: Cambia 'PermitRootLogin yes' a 'PermitRootLogin no'." >> $output_file
        else
            echo "OK: El acceso de root por SSH está deshabilitado." >> $output_file
        fi

        if [[ "$PasswordAuthentication" == "yes" ]]; then
            echo "CRÍTICO: La autenticación por contraseña está habilitada." >> $output_file
            echo "Problema Potencial: Puede facilitar ataques de fuerza bruta." >> $output_file
            echo "Recomendación: Cambia 'PasswordAuthentication yes' a 'PasswordAuthentication no'." >> $output_file
        else
            echo "OK: La autenticación por contraseña está deshabilitada." >> $output_file
        fi
    } >> $output_file
else
    echo "Advertencia: No se encontró el archivo de configuración de SSH." >> $output_file
fi

# 9. Verificación de Usuarios y Grupos
add_section "9. Verificación de Usuarios y Grupos"
{
    echo "Lista de usuarios del sistema:" >> $output_file
    cut -d: -f1 /etc/passwd >> $output_file

    echo -e "\nLista de grupos del sistema:" >> $output_file
    cut -d: -f1 /etc/group >> $output_file

    echo -e "\nComprobando usuarios con acceso sudo..." >> $output_file
    sudo_users=$(getent group sudo | awk -F: '{print $4}')
    if [ -z "$sudo_users" ]; then
        echo "CRÍTICO: No hay usuarios con acceso sudo." >> $output_file
    else
        echo "Usuarios con acceso sudo: $sudo_users" >> $output_file
    fi
} >> $output_file

# 10. Políticas de Contraseña
add_section "10. Políticas de Contraseña"
{
    password_policy=$(grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs)
    echo "Políticas de Contraseña:" >> $output_file
    echo "$password_policy" >> $output_file

    if grep -q 'PASS_MIN_LEN[[:space:]]*[0-9]\{1,\}' /etc/login.defs; then
        min_len=$(grep 'PASS_MIN_LEN' /etc/login.defs | awk '{print $2}')
        if [ "$min_len" -lt 8 ]; then
            echo "CRÍTICO: La longitud mínima de contraseña es inferior a 8 caracteres." >> $output_file
            echo "Recomendación: Aumenta 'PASS_MIN_LEN' a 8 o más." >> $output_file
        else
            echo "OK: La longitud mínima de contraseña es adecuada ($min_len)." >> $output_file
        fi
    else
        echo "Advertencia: No se encontró la política de longitud mínima de contraseña." >> $output_file
    fi
} >> $output_file

# 11. Intentos Fallidos de Acceso
add_section "11. Intentos Fallidos de Acceso"
{
    echo "Verificando intentos fallidos de acceso..." >> $output_file
    failed_attempts=$(grep 'Failed password' /var/log/auth.log | wc -l)
    if [ "$failed_attempts" -gt 0 ]; then
        echo "Advertencia: Se han registrado $failed_attempts intentos fallidos de acceso." >> $output_file
        echo "Recomendación: Revisa los registros para detectar patrones de ataques." >> $output_file
    else
        echo "OK: No se han registrado intentos fallidos de acceso." >> $output_file
    fi
} >> $output_file

# 12. Verificación de Políticas de Intentos Fallidos
add_section "12. Políticas de Intentos Fallidos"
if grep -q "auth required pam_tally2.so" /etc/pam.d/common-auth; then
    {
        echo "OK: Se encuentra configurado pam_tally2 para controlar los intentos fallidos."
        
        # Verificar la configuración adicional de pam_tally2
        fail_count=$(grep "auth required pam_tally2.so" /etc/pam.d/common-auth | grep -o "deny=[0-9]*" | cut -d= -f2)
        if [ -n "$fail_count" ]; then
            echo "Número de intentos fallidos permitidos antes del bloqueo: $fail_count"
        else
            echo "Advertencia: No se encontró el número de intentos fallidos permitidos."
        fi
    } >> $output_file
else
    {
        echo "CRÍTICO: pam_tally2 no está configurado."
        echo "Problema Potencial: No se limita el número de intentos fallidos de inicio de sesión."
        echo "Recomendación: Configura pam_tally2 en /etc/pam.d/common-auth."
    } >> $output_file
fi

# 13. Verificación de Bloqueo de Usuario
add_section "13. Verificación de Bloqueo de Usuario"
if grep -q "deny=" /etc/security/faillock.conf; then
    {
        echo "OK: Existe un límite de intentos fallidos configurado."
        # Extraer el número de intentos y el tiempo de bloqueo
        deny_value=$(grep "deny=" /etc/security/faillock.conf | cut -d= -f2)
        echo "Intentos fallidos permitidos antes del bloqueo: $deny_value"
        
        # Puedes verificar si hay una configuración para el tiempo de bloqueo
        if grep -q "fail_interval=" /etc/security/faillock.conf; then
            fail_interval=$(grep "fail_interval=" /etc/security/faillock.conf | cut -d= -f2)
            echo "Tiempo de bloqueo en minutos después de fallos: $fail_interval"
        else
            echo "Advertencia: No se encontró configuración para el tiempo de bloqueo."
        fi
    } >> $output_file
else
    {
        echo "CRÍTICO: No existe límite de intentos fallidos configurado."
        echo "Problema Potencial: Los usuarios pueden intentar iniciar sesión indefinidamente."
    } >> $output_file
fi

# 14. Verificación de Antivirus Instalado
add_section "14. Verificación de Antivirus Instalado"
antivirus_list=("clamav" "sophos" "chkrootkit" "rkhunter" "bitdefender" "f-secure")

found_antivirus=0
for antivirus in "${antivirus_list[@]}"; do
    if dpkg -l | grep -q "$antivirus"; then
        echo "Antivirus encontrado: $antivirus" >> $output_file
        found_antivirus=1
    fi
done

if [ $found_antivirus -eq 0 ]; then
    echo "CRÍTICO: No se encontró ningún software antivirus instalado." >> $output_file
    echo "Problema Potencial: Se recomienda instalar un software antivirus para proteger el sistema." >> $output_file
fi

# 15. Verificación de NTP
add_section "15. Verificación de NTP"
if systemctl is-active --quiet ntp; then
    echo "El servicio NTP está activo y en funcionamiento." >> $output_file
else
    echo "CRÍTICO: El servicio NTP no está activo." >> $output_file
    echo "Problema Potencial: La sincronización de tiempo puede no ser confiable." >> $output_file
fi

if command -v ntpq &> /dev/null; then
    ntp_status=$(ntpq -p)
    echo "Estado del servicio NTP:" >> $output_file
    echo "$ntp_status" >> $output_file
else
    echo "No se encontró el comando ntpq. Asegúrate de que NTP esté instalado." >> $output_file
fi


#16. Verificacion del Sistema
add_section "16. Verificación de Uso de Recursos"
echo "Uso de CPU:" >> $output_file
top -b -n 1 | head -n 10 >> $output_file

echo "Uso de Memoria:" >> $output_file
free -m >> $output_file

echo "Espacio en Disco:" >> $output_file
df -h >> $output_file


#17-18. Vericiacion de Reglas con Iptables o NFTABLES

#17. Verificación de Reglas de Iptables
add_section "17. Verificación de Reglas de Iptables"
iptables_rules=$(sudo iptables -L -n -v)
if [ -n "$iptables_rules" ]; then
    {
        echo "OK: Se encontraron las siguientes reglas de iptables:"
        echo "$iptables_rules"
    } >> $output_file
else
    {
        echo "CRÍTICO: No se encontraron reglas de iptables."
        echo "Problema Potencial: Sin protección a nivel de red."
    } >> $output_file
fi

#18. Verificacion de Reglas con NFTABLES
add_section "18. Verificación de Reglas de Nftables"
nft_rules=$(sudo nft list ruleset)
if [ -n "$nft_rules" ]; then
    {
        echo "OK: Se encontraron las siguientes reglas de nftables:"
        echo "$nft_rules"
    } >> $output_file
else
    {
        echo "CRÍTICO: No se encontraron reglas de nftables."
        echo "Problema Potencial: Sin protección a nivel de red."
    } >> $output_file
fi






# Finalización
echo "------------------------------------------------------" >> $output_file
echo "AUDITORÍA COMPLETADA" >> $output_file
echo "------------------------------------------------------" >> $output_file
echo "El informe se ha guardado en: $output_file"
