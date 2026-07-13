SELECT redirect_path
FROM auth_application_redirects
WHERE redirect_path = $1
LIMIT 1
