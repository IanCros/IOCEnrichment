using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IOCX.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Iocs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    OriginalValue = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    NormalizedValue = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    Type = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    LastInvestigatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Iocs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EnrichmentCacheEntries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProviderName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    IocId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RetrievedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    Result = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EnrichmentCacheEntries", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EnrichmentCacheEntries_Iocs_IocId",
                        column: x => x.IocId,
                        principalTable: "Iocs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Investigations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    IocId = table.Column<Guid>(type: "TEXT", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    CompletedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    RiskScore = table.Column<int>(type: "INTEGER", nullable: true),
                    RiskLevel = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ConfidenceScore = table.Column<int>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Investigations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Investigations_Iocs_IocId",
                        column: x => x.IocId,
                        principalTable: "Iocs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Relationships",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    SourceIocId = table.Column<Guid>(type: "TEXT", nullable: false),
                    TargetIocId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RelationshipType = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Confidence = table.Column<int>(type: "INTEGER", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Relationships", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Relationships_Iocs_SourceIocId",
                        column: x => x.SourceIocId,
                        principalTable: "Iocs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_Relationships_Iocs_TargetIocId",
                        column: x => x.TargetIocId,
                        principalTable: "Iocs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "Observations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    InvestigationId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ProviderName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Status = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    RetrievedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    Duration = table.Column<long>(type: "INTEGER", nullable: true),
                    NormalizedResult = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Observations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Observations_Investigations_InvestigationId",
                        column: x => x.InvestigationId,
                        principalTable: "Investigations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EnrichmentCacheEntries_ExpiresAt",
                table: "EnrichmentCacheEntries",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_EnrichmentCacheEntries_IocId",
                table: "EnrichmentCacheEntries",
                column: "IocId");

            migrationBuilder.CreateIndex(
                name: "IX_EnrichmentCacheEntries_ProviderName_IocId",
                table: "EnrichmentCacheEntries",
                columns: new[] { "ProviderName", "IocId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Investigations_IocId",
                table: "Investigations",
                column: "IocId");

            migrationBuilder.CreateIndex(
                name: "IX_Iocs_NormalizedValue",
                table: "Iocs",
                column: "NormalizedValue",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Iocs_Type",
                table: "Iocs",
                column: "Type");

            migrationBuilder.CreateIndex(
                name: "IX_Observations_InvestigationId",
                table: "Observations",
                column: "InvestigationId");

            migrationBuilder.CreateIndex(
                name: "IX_Relationships_SourceIocId",
                table: "Relationships",
                column: "SourceIocId");

            migrationBuilder.CreateIndex(
                name: "IX_Relationships_TargetIocId",
                table: "Relationships",
                column: "TargetIocId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EnrichmentCacheEntries");

            migrationBuilder.DropTable(
                name: "Observations");

            migrationBuilder.DropTable(
                name: "Relationships");

            migrationBuilder.DropTable(
                name: "Investigations");

            migrationBuilder.DropTable(
                name: "Iocs");
        }
    }
}
