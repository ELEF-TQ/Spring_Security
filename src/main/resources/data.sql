INSERT INTO roles(name) VALUES('ROLE_USER');
INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
INSERT INTO roles(name) VALUES('ROLE_ADMIN');

INSERT INTO permissions(name) VALUES('READ');
INSERT INTO permissions(name) VALUES('WRITE');
INSERT INTO permissions(name) VALUES('DELETE');

-- Assign permissions to roles
INSERT INTO role_permissions(role_id, permission_id) VALUES(
                                                               (SELECT id FROM roles WHERE name = 'ROLE_ADMIN'),
                                                               (SELECT id FROM permissions WHERE name = 'DELETE')
                                                           );