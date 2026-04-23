import os
import json
import pandas as pd
import requests
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import fpgrowth, association_rules
from sklearn.cluster import AgglomerativeClustering
from sklearn.preprocessing import MultiLabelBinarizer

#  CONFIGURATION 
path_to_vcdb = "../VCDB/data/json/validated/" # FAIRE CORRESPONDRE ICI AVEC VOTRE CHEMIN VCDB
N_CLUSTERS = 60  # Nombre de groupes 

#  ÉTAPE 0 : CHARGEMENT DE LA BASE MITRE ATT&CK  
print(" CHARGEMENT DE LA BASE MITRE ATT&CK  ")
mitre_db = {}
try:
    mitre_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    mitre_data = requests.get(mitre_url, timeout=15).json()
    
    for obj in mitre_data['objects']:
        if obj.get('type') == 'attack-pattern':
            name = obj.get('name').lower()
            ext_id = next((ref['external_id'] for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), "N/A")
            desc = obj.get('description', 'Pas de description.').split('.')[0] + '.'
            mitre_db[name] = {"id": ext_id, "desc": desc}
    print(f"Succès : {len(mitre_db)} techniques MITRE chargées.")
except Exception as e:
    print(f"Erreur de connexion MITRE : {e}. Le script risque de manquer de précisions.")

#  MAPPING 
def get_mitre_info_dynamique(items_list):
    ids, meds = [], []
    bridge = {
        "capture stored data": "data from local system",
        "ransomware": "data encrypted for impact",
        "c2": "command and control",
        "backdoor": "external remote services",
        "phishing": "phishing",
        "sqli": "sql injection",
        "brute force": "brute force",
        "desktop sharing": "remote desktop protocol",
        "social engineering": "social engineering",
        "downloader": "ingress tool transfer"
    }

    for item in items_list:
        item_lower = str(item).lower()
        search_term = bridge.get(item_lower, item_lower)
        found = False
        for mitre_name, info in mitre_db.items():
            if search_term in mitre_name or mitre_name in search_term:
                ids.append(info['id'])
                meds.append(info['desc'])
                found = True
                break
    
    unique_ids = sorted(list(set(ids)))
    unique_meds = sorted(list(set(meds)))
    id_final = ", ".join(unique_ids) if unique_ids else "N/A"
    med_final = " | ".join(unique_meds) if unique_meds else "Aucune description MITRE trouvée"
    
    return id_final, med_final

#  ÉTAPE 1 : CHARGEMENT DE LA VCDB  
all_incidents_techniques = []
incident_ids = [] 

if os.path.exists(path_to_vcdb):
    for filename in os.listdir(path_to_vcdb):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(path_to_vcdb, filename), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    items = []
                    actions = data.get('action', {})
                    for act_type in actions:
                        details = actions[act_type]
                        items.extend(details.get('techniques', []))
                        var = details.get('variety', [])
                        if isinstance(var, list): items.extend(var)
                        else: items.append(var)
                    clean = list(set([str(i) for i in items if i and str(i).lower() != 'unknown']))
                    if clean:
                        all_incidents_techniques.append(clean)
                        incident_ids.append(filename.replace(".json", "")) 
            except: continue
    print(f" ÉTAPE 1 : {len(all_incidents_techniques)} incidents chargés. ")

#  ÉTAPE 2 : EXECUTION DE L'ALGORITHME (FP-GROWTH) 
if len(all_incidents_techniques) > 0:
    te = TransactionEncoder()
    te_ary = te.fit(all_incidents_techniques).transform(all_incidents_techniques)
    df = pd.DataFrame(te_ary, columns=te.columns_)
    
    frequent_itemsets = fpgrowth(df, min_support=0.015, use_colnames=True) # MODIFIER ICI LE MIN_SUPPORT
    rules = association_rules(frequent_itemsets, metric="lift", min_threshold=1.2)

    if not rules.empty:
        print("\n TOP 10 DES CORRÉLATIONS ")
        top_10 = rules[['antecedents', 'consequents', 'lift']].sort_values(by='lift', ascending=False).head(10)
        print(top_10.to_string(index=False))

        #  NOUVEAU : CALCUL DU NOMBRE D'INCIDENTS  
        def find_source_incidents(row):
            pattern = set(list(row['antecedents']) + list(row['consequents']))
            matches = []
            for idx, incident in enumerate(all_incidents_techniques):
                if pattern.issubset(set(incident)):
                    matches.append(incident_ids[idx])
            return pd.Series([len(matches), ", ".join(matches)])

        print("Liaison avec les incidents sources...")
        rules[['NB_INCIDENTS', 'LISTE_ID_INCIDENTS']] = rules.apply(find_source_incidents, axis=1)

        #  ÉTAPE 3 : SÉCURITÉ MÉMOIRE ET CLUSTERING 
        if len(rules) > 5000:
            print(f"\nNote : {len(rules)} règles trouvées. Filtrage des 5000 meilleures...")
            rules = rules.sort_values(by='lift', ascending=False).head(5000).copy()

        rules['combined_items'] = rules.apply(lambda x: list(set(list(x['antecedents']) + list(x['consequents']))), axis=1)
        mlb = MultiLabelBinarizer()
        binary_matrix = mlb.fit_transform(rules['combined_items'])
        
        n_clusters_final = min(N_CLUSTERS, len(rules))
        cluster = AgglomerativeClustering(n_clusters=n_clusters_final, metric='euclidean', linkage='ward')
        rules['ID_GROUPE'] = cluster.fit_predict(binary_matrix)

        def qualifier_groupe(df_groupe):
            all_words = [item for sublist in df_groupe['combined_items'] for item in sublist]
            return " + ".join(pd.Series(all_words).value_counts().head(7).index.tolist()).upper() # MODIFIER HEAD

        noms_groupes = rules.groupby('ID_GROUPE').apply(qualifier_groupe, include_groups=False).to_dict()
        rules['SCÉNARIO_TYPE'] = rules['ID_GROUPE'].map(noms_groupes)

        #  ÉTAPE 4 : MITRE DYNAMIQUE 
        print("\n--- ENRICHISSEMENT VIA LA BASE MITRE ATT&CK ---")
        rules[['MITRE_ID', 'REMEDIATION']] = rules.apply(lambda x: pd.Series(get_mitre_info_dynamique(x['combined_items'])), axis=1)

        rules['ANTÉCÉDENTS'] = rules['antecedents'].apply(lambda x: ", ".join(list(x)))
        rules['CONSÉQUENTS'] = rules['consequents'].apply(lambda x: ", ".join(list(x)))
        
        final_cols = ['ID_GROUPE', 'SCÉNARIO_TYPE', 'ANTÉCÉDENTS', 'CONSÉQUENTS', 
                      'NB_INCIDENTS', 'LISTE_ID_INCIDENTS', 'MITRE_ID', 'REMEDIATION', 'lift']
        
        excel_df = rules[final_cols].sort_values(by=['ID_GROUPE', 'lift'], ascending=[True, False])
        
        #  EXPORT EXCEL 
        file_name = "Analyse_VCDB.xlsx"
        try:
            excel_df.to_excel(file_name, index=False, engine='openpyxl')
            print(f"\n--- ANALYSE TERMINÉE : Fichier '{file_name}' généré avec succès. ---")
        except PermissionError:
            print("\n" + "!"*60)
            print("ERREUR : Fermez le fichier 'Analyse_VCDB.xlsx' et relancez le script.")
            print("!"*60 + "\n")
        except Exception as e:
            print(f"\nErreur lors de l'enregistrement : {e}")
    else:
        print("Aucune règle trouvée.")