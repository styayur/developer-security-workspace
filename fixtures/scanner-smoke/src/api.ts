export function getUserQuery(id: string) {
  const query = "SELECT * FROM users WHERE id = '" + id + "'";
  return query;
}
