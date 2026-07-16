apiVersion: apps/v1
kind: Deployment
metadata:
  name: genesis-webserver
  namespace: genesis
  labels:
    app: webserver
    component: core
    environment: production
spec:
  replicas: 3
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: webserver
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  template:
    metadata:
      labels:
        app: webserver
        tier: frontend
    spec:
      securityContext:
        runAsUser: 1001
        runAsGroup: 3001
        fsGroup: 2001
      containers:
        - name: webserver
          image: registry.gitlab.com/tesla/genesis/webserver:latest
          imagePullPolicy: IfNotPresent
          ports:
            - name: http
              containerPort: 80
              protocol: TCP
          env:
            - name: ENVIRONMENT
              value: production
            - name: SERVICE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          resources:
            limits:
              cpu: "500m"
              memory: "512Mi"
            requests:
              cpu: "200m"
              memory: "256Mi"
          volumeMounts:
            - name: config-volume
              mountPath: /etc/nginx/conf.d
      volumes:
        - name: config-volume
          configMap:
            name: webserver-config
      imagePullSecrets:
        - name: gitlab-registry-secret
      restartPolicy: Always
