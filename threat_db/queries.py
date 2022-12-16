drop_all_query = """
    {
        "drop_all": true
    }
"""

introspect_query = """
    query IntrospectionQuery {
        __schema {
            types {
            name
            }
        }
    }
"""

health_query = """
    query {
        health {
            instance
            address
            version
            status
            lastEcho
            group
            uptime
            ongoing
            indexing
        }
    }
"""

auth_user_query = """
    query ($user_id: String!, $password: String!) {
        checkUserPassword(id: $user_id, password: $password) {
            id
            email
        }
    }
"""
