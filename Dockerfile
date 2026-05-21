# APKGuard Backend Dockerfile
FROM python:3.11-slim

# Install Java (for APKTool + JADX)
RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    wget \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir fastapi==0.136.1 uvicorn==0.47.0 python-multipart==0.0.29 scikit-learn==1.8.0 pandas==3.0.3 numpy==2.4.5 requests==2.34.2 tqdm==4.67.3 scipy==1.17.1 && pip install --no-cache-dir --no-deps xgboost==3.2.0

# Copy APKGuard source files
COPY decompiler.py .
COPY classifier.py .
COPY llm_explainer.py .
COPY api.py .

# Copy tools (APKTool + JADX) and trained model
COPY tools/ ./tools/
COPY models/ ./models/
COPY data/ ./data/

# Create required directories
RUN mkdir -p uploads output

# Make APKTool executable
RUN chmod +x /app/tools/apktool.bat 2>/dev/null || true

# Update paths in Python files for Linux container
RUN sed -i 's|C:/APKGuard|/app|g' decompiler.py classifier.py llm_explainer.py api.py
RUN sed -i 's|C:\\\\APKGuard|/app|g' decompiler.py classifier.py llm_explainer.py api.py

# Install APKTool for Linux
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /app/tools/apktool \
    && chmod +x /app/tools/apktool \
    && wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_3.0.2.jar -O /app/tools/apktool.jar

# Install JADX for Linux
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /app/tools/jadx_linux \
    && chmod +x /app/tools/jadx_linux/bin/jadx \
    && rm /tmp/jadx.zip

# Update tool paths for Linux in Python files
RUN sed -i 's|tools/apktool.bat|tools/apktool|g' decompiler.py \
    && sed -i 's|tools/jadx/bin/jadx.bat|tools/jadx_linux/bin/jadx|g' decompiler.py

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
