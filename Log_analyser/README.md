Ce projet analyse des journaux d’authentification afin de mieux comprendre les connexions SSH.
Il détecte les tentatives réussies, les échecs et les utilisateurs invalides, puis associe les adresses IP à leur pays.
Les événements sont enregistrés dans PostgreSQL pour faciliter leur consultation et leur analyse.
Un tableau de bord présente les résultats de façon visuelle afin d’aider à repérer les tendances et activités suspectes.