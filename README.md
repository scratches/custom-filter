There is a custom filter and a custom authentication
manager (which happen to be the same object for this app).
The authentication manager tries to do an OAuth2 authentication
and if it fails, instead of throwing an exception it creates
a CustomAuthentication that the filter looks for downstream.
    
For this sample the custom filter allows an access token with value
"GOOD". Obviously in a real app this would be replaced with some
other authentication strategy (proba
