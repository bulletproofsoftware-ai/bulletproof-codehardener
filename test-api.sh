#!/bin/bash
# Test API endpoints

BASE_URL="http://localhost:4000"

echo "=== 1. Testing Health ==="
curl -s "$BASE_URL/health" | jq .

echo -e "\n=== 2. Testing MCP Tools List ==="
curl -s "$BASE_URL/api/v1/mcp/tools" | jq '.data.tools[].name'

echo -e "\n=== 3. Testing User Registration ==="
REGISTER_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser2@example.com","password":"TestPassword123","name":"Test User 2"}')
echo "$REGISTER_RESULT" | jq .

echo -e "\n=== 4. Testing User Login ==="
LOGIN_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser2@example.com","password":"TestPassword123"}')
echo "$LOGIN_RESULT" | jq .

TOKEN=$(echo "$LOGIN_RESULT" | jq -r '.data.tokens.accessToken')
echo -e "\nToken: ${TOKEN:0:50}..."

echo -e "\n=== 5. Testing Get Me (Authenticated) ==="
curl -s "$BASE_URL/api/v1/auth/me" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n=== 6. Testing Get Projects ==="
curl -s "$BASE_URL/api/v1/projects" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n=== 7. Testing Create Project ==="
CREATE_PROJECT=$(curl -s -X POST "$BASE_URL/api/v1/projects" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Project","repositoryUrl":"https://github.com/test/repo"}')
echo "$CREATE_PROJECT" | jq .
PROJECT_ID=$(echo "$CREATE_PROJECT" | jq -r '.data.id')

echo -e "\n=== 8. Testing Get Scans ==="
curl -s "$BASE_URL/api/v1/scans" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n=== 9. Testing Dashboard Summary ==="
curl -s "$BASE_URL/api/v1/dashboard/summary" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n=== 10. Testing Findings ==="
curl -s "$BASE_URL/api/v1/findings" \
  -H "Authorization: Bearer $TOKEN" | jq .

echo -e "\n=== 11. Testing MCP Execute (with auth) ==="
curl -s -X POST "$BASE_URL/api/v1/mcp/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"tool\":\"codehardener_score\",\"arguments\":{\"projectId\":\"$PROJECT_ID\"}}" | jq .

echo -e "\n=== All Tests Complete ==="
