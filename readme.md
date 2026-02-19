# Identity Provider: SQL (Default)

## Overview
The **SQL Identity Provider** is the native authentication module for Photon, validating credentials against the internal database and managing local session states.

## Configuration
This provider leverages the primary application database connection string. No additional sections are required in `appsettings.json` for basic operation.

## Role
This module serves as the authoritative source for the **Field Sync** process, acting as the final destination for data mapped from external providers.