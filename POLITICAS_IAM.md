# POLITICAS_IAM.md

## Gestión de Identidades y Accesos (IAM)

### 1. Identificadores únicos
- Cada usuario y rol tiene un identificador único (campo `id` autoincremental).
- Los roles se almacenan en inglés en la base de datos y se traducen en la interfaz.

### 2. Alta y baja de usuarios
- Solo usuarios con rol admin/root pueden crear, modificar o eliminar cuentas.
- Cada alta, baja o cambio queda registrado en la tabla `audit_log`.
- La creación de usuarios requiere doble aprobación: un admin crea y otro aprueba.

### 3. Autenticación robusta (MFA)
- MFA obligatorio para todos los usuarios.
- Para cuentas privilegiadas, el acceso se bloquea si falla MFA.

### 4. Principio de mínimo privilegio
- Cada usuario solo ve y accede a lo estrictamente necesario según su rol.

### 5. Segregación de funciones
- La creación de usuarios requiere doble aprobación (no puede aprobar el mismo que crea).

### 6. Revisión periódica de privilegios
- Se realiza una revisión manual de privilegios cada 6 meses y se registra en la auditoría.

### 7. Auditoría centralizada e inmutable
- Todos los eventos quedan registrados y cifrados en la tabla `audit_log`.
- Solo admin/root puede consultar los logs.
- No es posible borrar registros de auditoría desde la app.

### 8. Supervisión de cuentas privilegiadas
- El uso de cuentas admin/root queda registrado en la auditoría.
- Se pueden elevar privilegios temporalmente (15 minutos).

### 9. Documentación y control de cambios
- Este archivo se actualiza con cada cambio relevante en las políticas IAM.
- Historial de cambios al final del documento.

---

## Historial de cambios
- 2025-09-28: Creación inicial del documento y políticas IAM.

